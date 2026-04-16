#include "sha256.h"

#ifdef _WIN32

#include <windows.h>
#include <bcrypt.h>
#include <winhttp.h>
#include <stdexcept>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winhttp.lib")

namespace platform {

Sha256::Sha256()
{
    BCRYPT_ALG_HANDLE alg;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM,
                                   nullptr, 0) != 0)
        throw std::runtime_error("BCryptOpenAlgorithmProvider failed");

    DWORD obj_size = 0, result_size = 0;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH,
                      reinterpret_cast<PUCHAR>(&obj_size),
                      sizeof(obj_size), &result_size, 0);

    struct Context {
        BCRYPT_ALG_HANDLE alg;
        BCRYPT_HASH_HANDLE hash;
        std::vector<uint8_t> obj;
    };
    auto *c = new Context;
    c->alg = alg;
    c->obj.resize(obj_size);

    if (BCryptCreateHash(alg, &c->hash, c->obj.data(),
                         obj_size, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        delete c;
        throw std::runtime_error("BCryptCreateHash failed");
    }
    ctx = c;
}

Sha256::~Sha256()
{
    struct Context {
        BCRYPT_ALG_HANDLE alg;
        BCRYPT_HASH_HANDLE hash;
        std::vector<uint8_t> obj;
    };
    auto *c = static_cast<Context *>(ctx);
    BCryptDestroyHash(c->hash);
    BCryptCloseAlgorithmProvider(c->alg, 0);
    delete c;
}

void Sha256::update(const uint8_t *data, size_t len)
{
    struct Context {
        BCRYPT_ALG_HANDLE alg;
        BCRYPT_HASH_HANDLE hash;
        std::vector<uint8_t> obj;
    };
    auto *c = static_cast<Context *>(ctx);
    BCryptHashData(c->hash, const_cast<PUCHAR>(data),
                   static_cast<ULONG>(len), 0);
}

std::array<uint8_t, 32> Sha256::finish()
{
    struct Context {
        BCRYPT_ALG_HANDLE alg;
        BCRYPT_HASH_HANDLE hash;
        std::vector<uint8_t> obj;
    };
    auto *c = static_cast<Context *>(ctx);
    std::array<uint8_t, 32> hash;
    BCryptFinishHash(c->hash, hash.data(), 32, 0);
    return hash;
}

std::array<uint8_t, 32> sha256(const uint8_t *data, size_t len)
{
    Sha256 h;
    h.update(data, len);
    return h.finish();
}

static std::wstring to_wide(const std::string &s)
{
    return std::wstring(s.begin(), s.end());
}

static HttpResponse winhttp_request(const std::string &host,
                                    const std::string &path,
                                    const std::string &bearer_token,
                                    const char *method,
                                    const std::string *body)
{
    HINTERNET session = WinHttpOpen(L"aas-sign/1.0",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME,
                                   WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        throw std::runtime_error("WinHttpOpen failed");

    auto whost = to_wide(host);
    HINTERNET conn = WinHttpConnect(session, whost.c_str(),
                                   INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) {
        WinHttpCloseHandle(session);
        throw std::runtime_error("WinHttpConnect failed");
    }

    auto wpath = to_wide(path);
    auto wmethod = to_wide(method);
    HINTERNET req = WinHttpOpenRequest(conn, wmethod.c_str(), wpath.c_str(),
                                       nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       WINHTTP_FLAG_SECURE);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        throw std::runtime_error("WinHttpOpenRequest failed");
    }

    std::wstring auth_header = L"Authorization: Bearer " + to_wide(bearer_token);
    WinHttpAddRequestHeaders(req, auth_header.c_str(), DWORD(-1),
                            WINHTTP_ADDREQ_FLAG_ADD);

    if (body) {
        std::wstring ct = L"Content-Type: application/json; charset=utf-8";
        WinHttpAddRequestHeaders(req, ct.c_str(), DWORD(-1),
                                WINHTTP_ADDREQ_FLAG_ADD);
    }

    BOOL ok = WinHttpSendRequest(req,
                                 WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 body ? (LPVOID)body->data() : WINHTTP_NO_REQUEST_DATA,
                                 body ? (DWORD)body->size() : 0,
                                 body ? (DWORD)body->size() : 0,
                                 0);
    if (!ok || !WinHttpReceiveResponse(req, nullptr)) {
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        throw std::runtime_error("WinHttp request failed");
    }

    DWORD status = 0, status_size = sizeof(status);
    WinHttpQueryHeaders(req,
                       WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                       WINHTTP_HEADER_NAME_BY_INDEX,
                       &status, &status_size, WINHTTP_NO_HEADER_INDEX);

    std::string response_body;
    DWORD bytes_available = 0;
    while (WinHttpQueryDataAvailable(req, &bytes_available) && bytes_available) {
        std::vector<char> buf(bytes_available);
        DWORD bytes_read = 0;
        WinHttpReadData(req, buf.data(), bytes_available, &bytes_read);
        response_body.append(buf.data(), bytes_read);
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);

    return {static_cast<int>(status), response_body};
}

HttpResponse https_post(const std::string &host, const std::string &path,
                        const std::string &bearer_token,
                        const std::string &json_body)
{
    return winhttp_request(host, path, bearer_token, "POST", &json_body);
}

HttpResponse https_get(const std::string &host, const std::string &path,
                       const std::string &bearer_token)
{
    return winhttp_request(host, path, bearer_token, "GET", nullptr);
}

HttpResponse http_post_binary(const std::string &host, int port,
                              const std::string &path,
                              const std::string &content_type,
                              const std::string &accept,
                              const std::vector<uint8_t> &body)
{
    HINTERNET session = WinHttpOpen(L"aas-sign/1.0",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME,
                                   WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        throw std::runtime_error("WinHttpOpen failed");

    auto whost = to_wide(host);
    HINTERNET conn = WinHttpConnect(session, whost.c_str(),
                                   INTERNET_PORT(port), 0);
    if (!conn) {
        WinHttpCloseHandle(session);
        throw std::runtime_error("WinHttpConnect failed");
    }

    auto wpath = to_wide(path);
    HINTERNET req = WinHttpOpenRequest(conn, L"POST", wpath.c_str(),
                                       nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       0);  // no WINHTTP_FLAG_SECURE: plain HTTP
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        throw std::runtime_error("WinHttpOpenRequest failed");
    }

    std::wstring ct = L"Content-Type: " + to_wide(content_type);
    WinHttpAddRequestHeaders(req, ct.c_str(), DWORD(-1),
                            WINHTTP_ADDREQ_FLAG_ADD);
    if (!accept.empty()) {
        std::wstring ah = L"Accept: " + to_wide(accept);
        WinHttpAddRequestHeaders(req, ah.c_str(), DWORD(-1),
                                WINHTTP_ADDREQ_FLAG_ADD);
    }

    BOOL ok = WinHttpSendRequest(req,
                                 WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 body.empty() ? WINHTTP_NO_REQUEST_DATA
                                              : (LPVOID)body.data(),
                                 (DWORD)body.size(),
                                 (DWORD)body.size(),
                                 0);
    if (!ok || !WinHttpReceiveResponse(req, nullptr)) {
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        throw std::runtime_error("WinHttp TSA request failed");
    }

    DWORD status = 0, status_size = sizeof(status);
    WinHttpQueryHeaders(req,
                       WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                       WINHTTP_HEADER_NAME_BY_INDEX,
                       &status, &status_size, WINHTTP_NO_HEADER_INDEX);

    std::string response_body;
    DWORD bytes_available = 0;
    while (WinHttpQueryDataAvailable(req, &bytes_available) && bytes_available) {
        std::vector<char> buf(bytes_available);
        DWORD bytes_read = 0;
        WinHttpReadData(req, buf.data(), bytes_available, &bytes_read);
        response_body.append(buf.data(), bytes_read);
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);

    return {static_cast<int>(status), response_body};
}

}  // namespace platform

#endif  // _WIN32
