#include "sha256.h"

#include <mbedtls/sha256.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

#include <sstream>
#include <stdexcept>

namespace platform {

// --- SHA-256 ---

Sha256::Sha256()
{
    auto *c = new mbedtls_sha256_context;
    mbedtls_sha256_init(c);
    mbedtls_sha256_starts(c, 0);
    ctx = c;
}

Sha256::~Sha256()
{
    auto *c = static_cast<mbedtls_sha256_context *>(ctx);
    mbedtls_sha256_free(c);
    delete c;
}

void Sha256::update(const uint8_t *data, size_t len)
{
    mbedtls_sha256_update(static_cast<mbedtls_sha256_context *>(ctx),
                          data, len);
}

std::array<uint8_t, 32> Sha256::finish()
{
    std::array<uint8_t, 32> hash;
    mbedtls_sha256_finish(static_cast<mbedtls_sha256_context *>(ctx),
                          hash.data());
    return hash;
}

std::array<uint8_t, 32> sha256(const uint8_t *data, size_t len)
{
    std::array<uint8_t, 32> hash;
    mbedtls_sha256(data, len, hash.data(), 0);
    return hash;
}

// --- Minimal HTTPS client using mbedTLS ---

static std::string mbed_error(int ret)
{
    char buf[256];
    mbedtls_strerror(ret, buf, sizeof(buf));
    return buf;
}

struct TlsConnection {
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    TlsConnection(const std::string &host)
    {
        mbedtls_net_init(&server_fd);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);

        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                        &entropy, nullptr, 0);
        if (ret != 0)
            throw std::runtime_error("mbedtls_ctr_drbg_seed: " +
                                     mbed_error(ret));

        ret = mbedtls_net_connect(&server_fd, host.c_str(), "443",
                                  MBEDTLS_NET_PROTO_TCP);
        if (ret != 0)
            throw std::runtime_error("connect to " + host + ":443: " +
                                     mbed_error(ret));

        ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0)
            throw std::runtime_error("ssl_config_defaults: " +
                                     mbed_error(ret));

        // Skip certificate verification (Azure certs are trusted and
        // this is a CI signing tool, not a browser).
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

        ret = mbedtls_ssl_setup(&ssl, &conf);
        if (ret != 0)
            throw std::runtime_error("ssl_setup: " + mbed_error(ret));

        ret = mbedtls_ssl_set_hostname(&ssl, host.c_str());
        if (ret != 0)
            throw std::runtime_error("ssl_set_hostname: " +
                                     mbed_error(ret));

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send,
                            mbedtls_net_recv, nullptr);

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE)
                throw std::runtime_error("TLS handshake with " + host +
                                         ": " + mbed_error(ret));
        }
    }

    ~TlsConnection()
    {
        mbedtls_ssl_close_notify(&ssl);
        mbedtls_net_free(&server_fd);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
    }

    void write_all(const std::string &data)
    {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(data.data());
        size_t remaining = data.size();
        while (remaining > 0) {
            int ret = mbedtls_ssl_write(&ssl, p, remaining);
            if (ret < 0) {
                if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
                throw std::runtime_error("ssl_write: " + mbed_error(ret));
            }
            p += ret;
            remaining -= ret;
        }
    }

    std::string read_all()
    {
        std::string result;
        uint8_t buf[4096];
        for (;;) {
            int ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
            if (ret == MBEDTLS_ERR_SSL_WANT_READ) continue;
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0)
                break;
            if (ret < 0)
                throw std::runtime_error("ssl_read: " + mbed_error(ret));
            result.append(reinterpret_cast<char *>(buf), ret);
        }
        return result;
    }
};

static HttpResponse parse_http_response(const std::string &raw)
{
    HttpResponse resp;
    // Parse status line.
    auto line_end = raw.find("\r\n");
    if (line_end == std::string::npos)
        throw std::runtime_error("malformed HTTP response");
    // "HTTP/1.1 200 OK"
    auto sp1 = raw.find(' ');
    if (sp1 == std::string::npos)
        throw std::runtime_error("malformed HTTP status line");
    resp.status = std::stoi(raw.substr(sp1 + 1, 3));

    // Find body (after \r\n\r\n).
    auto body_start = raw.find("\r\n\r\n");
    if (body_start != std::string::npos)
        resp.body = raw.substr(body_start + 4);

    // Handle chunked transfer encoding.
    if (raw.find("Transfer-Encoding: chunked") != std::string::npos ||
        raw.find("transfer-encoding: chunked") != std::string::npos) {
        std::string decoded;
        const std::string &src = resp.body;
        size_t pos = 0;
        while (pos < src.size()) {
            auto nl = src.find("\r\n", pos);
            if (nl == std::string::npos) break;
            size_t chunk_len = std::stoul(src.substr(pos, nl - pos),
                                          nullptr, 16);
            if (chunk_len == 0) break;
            pos = nl + 2;
            decoded.append(src, pos, chunk_len);
            pos += chunk_len + 2;  // skip \r\n after chunk
        }
        resp.body = decoded;
    }

    return resp;
}

static HttpResponse do_request(const std::string &host,
                               const std::string &method,
                               const std::string &path,
                               const std::string &bearer_token,
                               const std::string *body)
{
    TlsConnection conn(host);

    std::ostringstream req;
    req << method << " " << path << " HTTP/1.1\r\n";
    req << "Host: " << host << "\r\n";
    req << "Authorization: Bearer " << bearer_token << "\r\n";
    req << "Connection: close\r\n";
    if (body) {
        req << "Content-Type: application/json; charset=utf-8\r\n";
        req << "Content-Length: " << body->size() << "\r\n";
    }
    req << "\r\n";
    if (body) req << *body;

    conn.write_all(req.str());
    auto raw = conn.read_all();
    return parse_http_response(raw);
}

HttpResponse https_post(const std::string &host, const std::string &path,
                        const std::string &bearer_token,
                        const std::string &json_body)
{
    return do_request(host, "POST", path, bearer_token, &json_body);
}

HttpResponse https_get(const std::string &host, const std::string &path,
                       const std::string &bearer_token)
{
    return do_request(host, "GET", path, bearer_token, nullptr);
}

}  // namespace platform
