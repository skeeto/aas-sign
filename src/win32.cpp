#include "app.hpp"
#include "platform.hpp"

#ifdef _WIN32

// winsock2.h must precede windows.h: otherwise windows.h pulls in the
// older winsock.h and we get conflicting declarations.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <shlobj.h>
#include <winhttp.h>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace platform {

// --- Console output ---

namespace {

bool stream_is_console(HANDLE h)
{
    if (h == nullptr || h == INVALID_HANDLE_VALUE) return false;
    DWORD mode = 0;
    return GetConsoleMode(h, &mode) != 0;
}

void write_handle_all(DWORD which, std::string_view bytes)
{
    HANDLE h = GetStdHandle(which);
    if (h == nullptr || h == INVALID_HANDLE_VALUE) return;

    if (stream_is_console(h)) {
        // Transcode UTF-8 -> UTF-16 and use WriteConsoleW so non-ASCII
        // characters render correctly regardless of the console code page.
        if (bytes.empty()) return;
        int wn = MultiByteToWideChar(CP_UTF8, 0, bytes.data(),
                                     int(bytes.size()), nullptr, 0);
        if (wn <= 0) return;
        std::wstring w(size_t(wn), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, bytes.data(), int(bytes.size()),
                            w.data(), wn);
        const wchar_t *p = w.data();
        DWORD left = DWORD(w.size());
        while (left > 0) {
            DWORD written = 0;
            if (!WriteConsoleW(h, p, left, &written, nullptr)) return;
            if (written == 0) return;
            p += written;
            left -= written;
        }
    } else {
        // Redirected to a file or pipe: write UTF-8 bytes verbatim.
        const char *p = bytes.data();
        DWORD left = DWORD(bytes.size());
        while (left > 0) {
            DWORD written = 0;
            if (!WriteFile(h, p, left, &written, nullptr)) return;
            if (written == 0) return;
            p += written;
            left -= written;
        }
    }
}

}  // namespace

void write_stdout(std::string_view bytes)
{
    write_handle_all(STD_OUTPUT_HANDLE, bytes);
}

void write_stderr(std::string_view bytes)
{
    write_handle_all(STD_ERROR_HANDLE, bytes);
}

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

// Parse an https URL via WinHttpCrackUrl.  Populates host and
// path (including any query string).  Throws on non-https or malformed
// input.
static void parse_https_url(const std::string &url,
                            std::wstring &host, std::wstring &path_and_query)
{
    auto wurl = to_wide(url);
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    uc.dwHostNameLength  = DWORD(-1);
    uc.dwUrlPathLength   = DWORD(-1);
    uc.dwExtraInfoLength = DWORD(-1);
    uc.dwSchemeLength    = DWORD(-1);
    if (!WinHttpCrackUrl(wurl.c_str(), DWORD(wurl.size()), 0, &uc))
        throw std::runtime_error("WinHttpCrackUrl failed on URL: " + url);
    if (uc.nScheme != INTERNET_SCHEME_HTTPS)
        throw std::runtime_error("expected https:// URL, got: " + url);
    host.assign(uc.lpszHostName, uc.dwHostNameLength);
    path_and_query.assign(uc.lpszUrlPath, uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength)
        path_and_query.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);
    if (path_and_query.empty()) path_and_query = L"/";
}

static HttpResponse winhttp_url_request(const std::string &url,
                                        const wchar_t *method,
                                        const std::string *bearer_token,
                                        const std::string *content_type,
                                        const std::string *body)
{
    std::wstring whost, wpath;
    parse_https_url(url, whost, wpath);

    HINTERNET session = WinHttpOpen(L"aas-sign/1.0",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME,
                                   WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) throw std::runtime_error("WinHttpOpen failed");

    HINTERNET conn = WinHttpConnect(session, whost.c_str(),
                                   INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) {
        WinHttpCloseHandle(session);
        throw std::runtime_error("WinHttpConnect failed");
    }

    HINTERNET req = WinHttpOpenRequest(conn, method, wpath.c_str(),
                                       nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       WINHTTP_FLAG_SECURE);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        throw std::runtime_error("WinHttpOpenRequest failed");
    }

    if (bearer_token) {
        std::wstring hdr = L"Authorization: Bearer " + to_wide(*bearer_token);
        WinHttpAddRequestHeaders(req, hdr.c_str(), DWORD(-1),
                                 WINHTTP_ADDREQ_FLAG_ADD);
    }
    if (content_type) {
        std::wstring hdr = L"Content-Type: " + to_wide(*content_type);
        WinHttpAddRequestHeaders(req, hdr.c_str(), DWORD(-1),
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
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(req, &avail) && avail) {
        std::vector<char> buf(avail);
        DWORD got = 0;
        WinHttpReadData(req, buf.data(), avail, &got);
        response_body.append(buf.data(), got);
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);

    return {static_cast<int>(status), response_body};
}

HttpResponse https_get_url(const std::string &url,
                           const std::string &bearer_token)
{
    return winhttp_url_request(url, L"GET", &bearer_token, nullptr, nullptr);
}

HttpResponse https_post_url(const std::string &url,
                            const std::string &content_type,
                            const std::string &body)
{
    return winhttp_url_request(url, L"POST", nullptr, &content_type, &body);
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

// --- File I/O ---

static std::wstring utf8_to_wide(const std::string &s)
{
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()),
                                nullptr, 0);
    if (n <= 0)
        throw std::runtime_error("UTF-8 -> UTF-16 conversion failed");
    std::wstring w(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), w.data(), n);
    return w;
}

static std::string win_error(DWORD code)
{
    std::ostringstream s;
    s << "Win32 error " << code;
    return s.str();
}

static HANDLE file_handle(void *impl) { return HANDLE(impl); }

File::File(const std::string &utf8_path)
    : path_(utf8_path), impl_(INVALID_HANDLE_VALUE)
{
    auto wpath = utf8_to_wide(path_);
    HANDLE h = CreateFileW(wpath.c_str(),
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ,
                           nullptr,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE)
        throw std::runtime_error("open " + path_ + ": " +
                                 win_error(GetLastError()));
    impl_ = h;
}

File::~File()
{
    HANDLE h = file_handle(impl_);
    if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

uint64_t File::size()
{
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(file_handle(impl_), &sz))
        throw std::runtime_error("GetFileSizeEx " + path_ + ": " +
                                 win_error(GetLastError()));
    return uint64_t(sz.QuadPart);
}

void File::read_at(uint64_t offset, void *buf, size_t len)
{
    HANDLE h = file_handle(impl_);
    uint8_t *p = static_cast<uint8_t *>(buf);
    while (len > 0) {
        OVERLAPPED ov{};
        ov.Offset = DWORD(offset & 0xFFFFFFFFu);
        ov.OffsetHigh = DWORD(offset >> 32);
        DWORD to_read = DWORD(len > 0x40000000u ? 0x40000000u : len);
        DWORD got = 0;
        if (!ReadFile(h, p, to_read, &got, &ov)) {
            DWORD err = GetLastError();
            throw std::runtime_error("ReadFile " + path_ + ": " +
                                     win_error(err));
        }
        if (got == 0)
            throw std::runtime_error("ReadFile " + path_ +
                                     ": unexpected EOF");
        p += got;
        offset += got;
        len -= got;
    }
}

void File::write_at(uint64_t offset, const void *buf, size_t len)
{
    HANDLE h = file_handle(impl_);
    const uint8_t *p = static_cast<const uint8_t *>(buf);
    while (len > 0) {
        OVERLAPPED ov{};
        ov.Offset = DWORD(offset & 0xFFFFFFFFu);
        ov.OffsetHigh = DWORD(offset >> 32);
        DWORD to_write = DWORD(len > 0x40000000u ? 0x40000000u : len);
        DWORD wrote = 0;
        if (!WriteFile(h, p, to_write, &wrote, &ov)) {
            DWORD err = GetLastError();
            throw std::runtime_error("WriteFile " + path_ + ": " +
                                     win_error(err));
        }
        if (wrote == 0)
            throw std::runtime_error("WriteFile " + path_ +
                                     ": zero bytes written");
        p += wrote;
        offset += wrote;
        len -= wrote;
    }
}

void File::truncate(uint64_t new_size)
{
    HANDLE h = file_handle(impl_);
    LARGE_INTEGER pos;
    pos.QuadPart = LONGLONG(new_size);
    if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN))
        throw std::runtime_error("SetFilePointerEx " + path_ + ": " +
                                 win_error(GetLastError()));
    if (!SetEndOfFile(h))
        throw std::runtime_error("SetEndOfFile " + path_ + ": " +
                                 win_error(GetLastError()));
}

void File::flush()
{
    HANDLE h = file_handle(impl_);
    if (!FlushFileBuffers(h)) {
        DWORD err = GetLastError();
        // FlushFileBuffers on a handle that doesn't support flushing
        // (e.g. a stdout pipe -- not our case, but be lenient) returns
        // ERROR_INVALID_HANDLE or ERROR_ACCESS_DENIED.  For a real file
        // both represent an error worth reporting.
        throw std::runtime_error("FlushFileBuffers " + path_ + ": " +
                                 win_error(err));
    }
}

void write_whole_file(const std::string &utf8_path,
                      const uint8_t *data, size_t len)
{
    auto wpath = utf8_to_wide(utf8_path);
    HANDLE h = CreateFileW(wpath.c_str(),
                           GENERIC_WRITE,
                           0,
                           nullptr,
                           CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE)
        throw std::runtime_error("open(write) " + utf8_path + ": " +
                                 win_error(GetLastError()));
    const uint8_t *p = data;
    size_t remaining = len;
    while (remaining > 0) {
        DWORD chunk = DWORD(remaining > 0x40000000u ? 0x40000000u : remaining);
        DWORD wrote = 0;
        if (!WriteFile(h, p, chunk, &wrote, nullptr)) {
            DWORD err = GetLastError();
            CloseHandle(h);
            throw std::runtime_error("WriteFile " + utf8_path + ": " +
                                     win_error(err));
        }
        p += wrote;
        remaining -= wrote;
    }
    if (!CloseHandle(h))
        throw std::runtime_error("CloseHandle " + utf8_path + ": " +
                                 win_error(GetLastError()));
}

void atomic_write_private_file(const std::string &utf8_path,
                               const uint8_t *data, size_t len)
{
    std::string tmp = utf8_path + ".tmp";
    auto wtmp = utf8_to_wide(tmp);
    HANDLE h = CreateFileW(wtmp.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        throw std::runtime_error("open(write) " + tmp + ": " +
                                 win_error(GetLastError()));
    const uint8_t *p = data;
    size_t remaining = len;
    while (remaining > 0) {
        DWORD chunk = DWORD(remaining > 0x40000000u ? 0x40000000u : remaining);
        DWORD wrote = 0;
        if (!WriteFile(h, p, chunk, &wrote, nullptr)) {
            DWORD err = GetLastError();
            CloseHandle(h);
            throw std::runtime_error("WriteFile " + tmp + ": " +
                                     win_error(err));
        }
        p += wrote;
        remaining -= wrote;
    }
    if (!CloseHandle(h))
        throw std::runtime_error("CloseHandle " + tmp + ": " +
                                 win_error(GetLastError()));

    auto wfinal = utf8_to_wide(utf8_path);
    if (!MoveFileExW(wtmp.c_str(), wfinal.c_str(),
                     MOVEFILE_REPLACE_EXISTING))
        throw std::runtime_error("MoveFileExW " + utf8_path + ": " +
                                 win_error(GetLastError()));
}

void remove_file(const std::string &utf8_path)
{
    auto wpath = utf8_to_wide(utf8_path);
    if (!DeleteFileW(wpath.c_str())) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
            return;  // already absent; treat as success
        throw std::runtime_error("DeleteFileW " + utf8_path + ": " +
                                 win_error(err));
    }
}

// --- LoopbackServer / launch_browser / config_dir (OAuth login) ---

// Lazy one-time WSAStartup.  Safe to call many times.
static void wsa_startup_once()
{
    static bool done = false;
    if (done) return;
    WSADATA wsa;
    int r = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (r != 0)
        throw std::runtime_error("WSAStartup failed: " + win_error(DWORD(r)));
    done = true;
}

static SOCKET lbs_sock(const void *impl) {
    // 0 means unset; store socket+1.
    return impl ? SOCKET(reinterpret_cast<uintptr_t>(impl) - 1)
                : INVALID_SOCKET;
}
static void *lbs_box(SOCKET s) {
    return reinterpret_cast<void *>(uintptr_t(s) + 1);
}

LoopbackServer::LoopbackServer()
    : impl_(nullptr), port_(0), client_impl_(nullptr)
{
    wsa_startup_once();
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        throw std::runtime_error("socket: " + win_error(DWORD(WSAGetLastError())));
    BOOL one = TRUE;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char *>(&one), sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        int e = WSAGetLastError(); closesocket(s);
        throw std::runtime_error("bind loopback: " + win_error(DWORD(e)));
    }
    sockaddr_in bound{};
    int blen = int(sizeof(bound));
    if (::getsockname(s, reinterpret_cast<sockaddr *>(&bound), &blen) != 0) {
        int e = WSAGetLastError(); closesocket(s);
        throw std::runtime_error("getsockname: " + win_error(DWORD(e)));
    }
    port_ = ntohs(bound.sin_port);

    if (::listen(s, 5) != 0) {
        int e = WSAGetLastError(); closesocket(s);
        throw std::runtime_error("listen: " + win_error(DWORD(e)));
    }
    impl_ = lbs_box(s);
}

LoopbackServer::~LoopbackServer()
{
    SOCKET c = lbs_sock(client_impl_);
    if (c != INVALID_SOCKET) closesocket(c);
    SOCKET s = lbs_sock(impl_);
    if (s != INVALID_SOCKET) closesocket(s);
}

int LoopbackServer::port() const { return port_; }

std::string LoopbackServer::accept_request()
{
    SOCKET ls = lbs_sock(impl_);
    SOCKET cs = ::accept(ls, nullptr, nullptr);
    if (cs == INVALID_SOCKET)
        throw std::runtime_error("accept: " +
                                 win_error(DWORD(WSAGetLastError())));
    client_impl_ = lbs_box(cs);

    std::string buf;
    char tmp[4096];
    while (buf.find("\r\n\r\n") == std::string::npos && buf.size() < 16384) {
        int n = ::recv(cs, tmp, int(sizeof(tmp)), 0);
        if (n < 0)
            throw std::runtime_error("recv: " +
                                     win_error(DWORD(WSAGetLastError())));
        if (n == 0) break;
        buf.append(tmp, size_t(n));
    }

    auto line_end = buf.find("\r\n");
    std::string line = buf.substr(0, line_end);
    auto sp1 = line.find(' ');
    auto sp2 = (sp1 == std::string::npos) ? std::string::npos
                                          : line.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos)
        throw std::runtime_error("malformed HTTP request line");
    return line.substr(sp1 + 1, sp2 - sp1 - 1);
}

void LoopbackServer::respond(const std::string &html)
{
    SOCKET cs = lbs_sock(client_impl_);
    if (cs == INVALID_SOCKET)
        throw std::runtime_error("respond() before accept_request()");
    std::ostringstream resp;
    resp << "HTTP/1.1 200 OK\r\n"
         << "Content-Type: text/html; charset=utf-8\r\n"
         << "Content-Length: " << html.size() << "\r\n"
         << "Connection: close\r\n\r\n"
         << html;
    std::string s = resp.str();
    const char *p = s.data();
    int remaining = int(s.size());
    while (remaining > 0) {
        int n = ::send(cs, p, remaining, 0);
        if (n < 0)
            throw std::runtime_error("send: " +
                                     win_error(DWORD(WSAGetLastError())));
        p += n;
        remaining -= n;
    }
    closesocket(cs);
    client_impl_ = nullptr;
}

void launch_browser(const std::string &url)
{
    auto wurl = to_wide(url);
    // ShellExecuteW returns a value > 32 on success.
    HINSTANCE r = ShellExecuteW(nullptr, L"open", wurl.c_str(),
                                nullptr, nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<intptr_t>(r) <= 32)
        throw std::runtime_error("ShellExecuteW failed for URL: " + url);
}

std::string config_dir()
{
    wchar_t wbuf[MAX_PATH];
    HRESULT hr = SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr,
                                  SHGFP_TYPE_CURRENT, wbuf);
    if (FAILED(hr))
        throw std::runtime_error("SHGetFolderPathW failed: " +
                                 win_error(DWORD(hr)));

    // Convert to UTF-8.
    int n = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1,
                                nullptr, 0, nullptr, nullptr);
    std::string base(size_t(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, base.data(), n, nullptr, nullptr);

    std::string dir = base + "\\aas-sign";
    std::wstring wdir(dir.begin(), dir.end());
    if (!CreateDirectoryW(wdir.c_str(), nullptr)) {
        DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS)
            throw std::runtime_error("CreateDirectoryW " + dir + ": " +
                                     win_error(err));
    }
    return dir;
}

}  // namespace platform

// --- Entry point ---

// Windows argv is in the system code page, which loses non-ASCII
// characters and is code-page-dependent.  Fetch the wide command line
// directly, transcode to UTF-8, and hand off to aas_sign_main().
int main()
{
    int wargc = 0;
    LPWSTR *wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    if (!wargv) {
        std::ostringstream msg;
        msg << "CommandLineToArgvW failed (error " << GetLastError() << ")\n";
        platform::write_stderr(msg.str());
        return 1;
    }

    // Stable storage for the UTF-8 arg strings and the char* argv array.
    std::vector<std::string> args(size_t(wargc > 0 ? wargc : 0));
    std::vector<char *> argv(size_t(wargc > 0 ? wargc : 0) + 1, nullptr);
    for (int i = 0; i < wargc; i++) {
        const wchar_t *w = wargv[i];
        int n = WideCharToMultiByte(CP_UTF8, 0, w, -1,
                                    nullptr, 0, nullptr, nullptr);
        if (n <= 0) {
            LocalFree(wargv);
            std::ostringstream msg;
            msg << "WideCharToMultiByte failed on arg " << i << "\n";
            platform::write_stderr(msg.str());
            return 1;
        }
        args[i].resize(size_t(n) - 1);  // exclude trailing NUL
        WideCharToMultiByte(CP_UTF8, 0, w, -1, args[i].data(), n,
                            nullptr, nullptr);
        argv[i] = args[i].data();
    }
    LocalFree(wargv);

    // Make stderr/stdout render UTF-8 error messages correctly in a
    // console window.  Redirection to files is untouched.
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    return aas_sign_main(wargc, argv.data());
}

#endif  // _WIN32
