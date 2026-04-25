#include "app.hpp"
#include "narrow.hpp"
#include "platform.hpp"

#include <mbedtls/sha256.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/x509_crt.h>

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sstream>
#include <stdexcept>

namespace platform {

// --- Console output ---

namespace {
void write_fd_all(int fd, std::string_view bytes)
{
    const char *p = bytes.data();
    size_t left = bytes.size();
    while (left > 0) {
        ssize_t n = ::write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR) continue;
            return;  // best-effort; match std::cerr's silent-fail
        }
        if (n == 0) return;
        p += n;
        left -= size_t(n);
    }
}
}  // namespace

void write_stdout(std::string_view bytes) { write_fd_all(STDOUT_FILENO, bytes); }
void write_stderr(std::string_view bytes) { write_fd_all(STDERR_FILENO, bytes); }

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

// TLS verification mode.  Defaults to verifying against the system CA
// bundle.  --insecure flips this off for the rest of the process via
// platform::tls_disable_verification().  Set once at startup, before
// any worker threads spawn -- so a plain bool is fine, no atomics or
// mutex needed.
static bool g_tls_insecure = false;

void tls_disable_verification() { g_tls_insecure = true; }

// Locate a system CA bundle.  Order, taken from libcurl's
// well-known-paths heuristic: env override first, then the bundles
// each major distro family ships at a known absolute path, then a
// few Homebrew/MacPorts fallbacks.  All of these are PEM files
// containing many concatenated certificates -- the format
// mbedtls_x509_crt_parse_file accepts directly.  Returns the empty
// string when none of the paths exists.
static std::string find_ca_bundle()
{
    if (const char *p = std::getenv("SSL_CERT_FILE"); p && *p) {
        struct stat st;
        if (::stat(p, &st) == 0)
            return p;
    }
    static const char *paths[] = {
        "/etc/ssl/certs/ca-certificates.crt",       // Debian/Ubuntu/Arch
        "/etc/pki/tls/certs/ca-bundle.crt",         // RHEL/CentOS/Fedora
        "/etc/ssl/ca-bundle.pem",                   // OpenSUSE
        "/etc/ssl/cert.pem",                        // Alpine/FreeBSD/macOS Homebrew
        "/etc/pki/tls/cacert.pem",
        "/usr/local/share/certs/ca-root-nss.crt",   // FreeBSD ports
        "/usr/local/etc/openssl@3/cert.pem",        // Homebrew (Intel)
        "/opt/homebrew/etc/openssl@3/cert.pem",     // Homebrew (Apple Silicon)
    };
    for (const char *p : paths) {
        struct stat st;
        if (::stat(p, &st) == 0)
            return p;
    }
    return "";
}

struct TlsConnection {
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

    TlsConnection(const std::string &host)
    {
        mbedtls_net_init(&server_fd);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);
        mbedtls_x509_crt_init(&cacert);

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

        if (g_tls_insecure) {
            mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
        } else {
            std::string bundle = find_ca_bundle();
            if (bundle.empty())
                throw std::runtime_error(
                    "no CA certificate bundle found at any standard "
                    "location; install ca-certificates, set "
                    "SSL_CERT_FILE, or pass --insecure to skip "
                    "TLS verification");
            // Positive return = number of certs that failed to parse;
            // we tolerate that as long as some certs loaded.  Negative
            // = hard error.
            ret = mbedtls_x509_crt_parse_file(&cacert, bundle.c_str());
            if (ret < 0)
                throw std::runtime_error(
                    "failed to parse CA bundle " + bundle + ": " +
                    mbed_error(ret));
            mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
            mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        }
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

        ret = mbedtls_ssl_setup(&ssl, &conf);
        if (ret != 0)
            throw std::runtime_error("ssl_setup: " + mbed_error(ret));

        // SNI + (when verifying) cert hostname check.
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
        mbedtls_x509_crt_free(&cacert);
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
            remaining -= narrow<size_t>(ret);
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
            result.append(reinterpret_cast<char *>(buf), narrow<size_t>(ret));
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

// Parse "https://host[:port]/path?query" into components.  The port is
// ignored (TlsConnection hardcodes 443) since every endpoint we speak
// to HTTPS on is on the default port.
static void parse_https_url(const std::string &url,
                            std::string &host, std::string &path_and_query)
{
    const std::string scheme = "https://";
    if (url.compare(0, scheme.size(), scheme) != 0)
        throw std::runtime_error("expected https:// URL, got: " + url);
    size_t host_start = scheme.size();
    size_t path_start = url.find('/', host_start);
    host = (path_start == std::string::npos)
        ? url.substr(host_start)
        : url.substr(host_start, path_start - host_start);
    path_and_query = (path_start == std::string::npos)
        ? "/" : url.substr(path_start);
    // If host carries a :port suffix we just drop it (we always hit 443).
    auto colon = host.find(':');
    if (colon != std::string::npos)
        host.erase(colon);
}

HttpResponse https_get_url(const std::string &url,
                           const std::string &bearer_token)
{
    std::string host, path;
    parse_https_url(url, host, path);

    TlsConnection conn(host);
    std::ostringstream req;
    req << "GET " << path << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "User-Agent: aas-sign/1.0\r\n"
        << "Accept: application/json\r\n"
        << "Authorization: Bearer " << bearer_token << "\r\n"
        << "Connection: close\r\n\r\n";
    conn.write_all(req.str());
    return parse_http_response(conn.read_all());
}

HttpResponse https_post_url(const std::string &url,
                            const std::string &content_type,
                            const std::string &body)
{
    std::string host, path;
    parse_https_url(url, host, path);

    TlsConnection conn(host);
    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "User-Agent: aas-sign/1.0\r\n"
        << "Accept: application/json\r\n"
        << "Content-Type: " << content_type << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;
    conn.write_all(req.str());
    return parse_http_response(conn.read_all());
}

HttpResponse http_post_binary(const std::string &host, int port,
                              const std::string &path,
                              const std::string &content_type,
                              const std::string &accept,
                              const std::vector<uint8_t> &body)
{
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port);
    addrinfo *res = nullptr;
    int gai = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (gai != 0)
        throw std::runtime_error("getaddrinfo " + host + ": " +
                                 gai_strerror(gai));

    int fd = -1;
    for (addrinfo *a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        throw std::runtime_error("cannot connect to " + host + ":" + port_str);

    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n";
    req << "Host: " << host;
    if (port != 80) req << ":" << port;
    req << "\r\n";
    req << "User-Agent: aas-sign/1.0\r\n";
    req << "Content-Type: " << content_type << "\r\n";
    if (!accept.empty())
        req << "Accept: " << accept << "\r\n";
    req << "Content-Length: " << body.size() << "\r\n";
    req << "Connection: close\r\n\r\n";
    std::string header = req.str();

    auto write_n = [&](const uint8_t *p, size_t n) {
        while (n > 0) {
            ssize_t w = write(fd, p, n);
            if (w <= 0) {
                close(fd);
                throw std::runtime_error("write to TSA failed");
            }
            p += w;
            n -= size_t(w);
        }
    };
    write_n(reinterpret_cast<const uint8_t *>(header.data()), header.size());
    if (!body.empty())
        write_n(body.data(), body.size());

    std::string raw;
    char buf[4096];
    for (;;) {
        ssize_t r = read(fd, buf, sizeof(buf));
        if (r < 0) {
            close(fd);
            throw std::runtime_error("read from TSA failed");
        }
        if (r == 0) break;
        raw.append(buf, size_t(r));
    }
    close(fd);

    return parse_http_response(raw);
}

// --- File I/O ---

static int file_fd(const File &f, void *impl)
{
    // impl_ holds (fd + 1) so we can distinguish "unset" (nullptr) from fd 0.
    (void)f;
    return int(reinterpret_cast<intptr_t>(impl)) - 1;
}

static std::string errno_msg(const char *op, const std::string &path)
{
    std::ostringstream s;
    s << op << " " << path << ": " << std::strerror(errno);
    return s.str();
}

File::File(const std::string &utf8_path) : path_(utf8_path), impl_(nullptr)
{
    int fd = ::open(path_.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0)
        throw std::runtime_error(errno_msg("open", path_));
    impl_ = reinterpret_cast<void *>(intptr_t(fd + 1));
}

File::~File()
{
    int fd = file_fd(*this, impl_);
    if (fd >= 0) ::close(fd);
}

uint64_t File::size()
{
    int fd = file_fd(*this, impl_);
    struct stat st;
    if (::fstat(fd, &st) < 0)
        throw std::runtime_error(errno_msg("fstat", path_));
    return uint64_t(st.st_size);
}

void File::read_at(uint64_t offset, void *buf, size_t len)
{
    int fd = file_fd(*this, impl_);
    uint8_t *p = static_cast<uint8_t *>(buf);
    while (len > 0) {
        ssize_t n = ::pread(fd, p, len, off_t(offset));
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(errno_msg("pread", path_));
        }
        if (n == 0)
            throw std::runtime_error("pread " + path_ +
                                     ": unexpected EOF");
        p += n;
        offset += uint64_t(n);
        len -= size_t(n);
    }
}

void File::write_at(uint64_t offset, const void *buf, size_t len)
{
    int fd = file_fd(*this, impl_);
    const uint8_t *p = static_cast<const uint8_t *>(buf);
    while (len > 0) {
        ssize_t n = ::pwrite(fd, p, len, off_t(offset));
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(errno_msg("pwrite", path_));
        }
        if (n == 0)
            throw std::runtime_error("pwrite " + path_ +
                                     ": zero bytes written");
        p += n;
        offset += uint64_t(n);
        len -= size_t(n);
    }
}

void File::truncate(uint64_t new_size)
{
    int fd = file_fd(*this, impl_);
    if (::ftruncate(fd, off_t(new_size)) < 0)
        throw std::runtime_error(errno_msg("ftruncate", path_));
}

void File::flush()
{
    int fd = file_fd(*this, impl_);
    // fsync would be overkill for a local file-edit; fdatasync is fine
    // where available, but fsync is the portable choice.
    if (::fsync(fd) < 0 && errno != EINVAL) {
        // Some filesystems (e.g. /tmp on some platforms) reject fsync
        // with EINVAL; treat as best-effort.
        throw std::runtime_error(errno_msg("fsync", path_));
    }
}

void write_whole_file(const std::string &utf8_path,
                      const uint8_t *data, size_t len)
{
    int fd = ::open(utf8_path.c_str(),
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        throw std::runtime_error(errno_msg("open(write)", utf8_path));
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::write(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            int saved = errno;
            ::close(fd);
            errno = saved;
            throw std::runtime_error(errno_msg("write", utf8_path));
        }
        off += size_t(n);
    }
    if (::close(fd) < 0)
        throw std::runtime_error(errno_msg("close", utf8_path));
}

void atomic_write_private_file(const std::string &utf8_path,
                               const uint8_t *data, size_t len)
{
    std::string tmp = utf8_path + ".tmp";
    int fd = ::open(tmp.c_str(),
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        throw std::runtime_error(errno_msg("open(write)", tmp));
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::write(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            int saved = errno; ::close(fd); errno = saved;
            throw std::runtime_error(errno_msg("write", tmp));
        }
        off += size_t(n);
    }
    ::fsync(fd);
    if (::close(fd) < 0)
        throw std::runtime_error(errno_msg("close", tmp));
    if (::rename(tmp.c_str(), utf8_path.c_str()) < 0)
        throw std::runtime_error(errno_msg("rename", utf8_path));
}

void remove_file(const std::string &utf8_path)
{
    if (::unlink(utf8_path.c_str()) < 0 && errno != ENOENT)
        throw std::runtime_error(errno_msg("unlink", utf8_path));
}

// --- LoopbackServer / launch_browser / config_dir (OAuth login) ---

static int lbs_fd(const void *impl) {
    return int(reinterpret_cast<intptr_t>(impl)) - 1;  // 0 means unset
}
static void *lbs_box(int fd) {
    return reinterpret_cast<void *>(intptr_t(fd + 1));
}

LoopbackServer::LoopbackServer()
    : impl_(nullptr), port_(0), client_impl_(nullptr)
{
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        throw std::runtime_error(std::string("socket: ") + std::strerror(errno));
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;  // OS assigns
    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        int e = errno; ::close(fd); errno = e;
        throw std::runtime_error(std::string("bind loopback: ") +
                                 std::strerror(errno));
    }
    sockaddr_in bound{};
    socklen_t blen = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &blen) < 0) {
        int e = errno; ::close(fd); errno = e;
        throw std::runtime_error(std::string("getsockname: ") +
                                 std::strerror(errno));
    }
    port_ = ntohs(bound.sin_port);

    if (::listen(fd, 5) < 0) {
        int e = errno; ::close(fd); errno = e;
        throw std::runtime_error(std::string("listen: ") +
                                 std::strerror(errno));
    }
    impl_ = lbs_box(fd);
}

LoopbackServer::~LoopbackServer()
{
    int cfd = lbs_fd(client_impl_);
    if (cfd >= 0) ::close(cfd);
    int fd = lbs_fd(impl_);
    if (fd >= 0) ::close(fd);
}

int LoopbackServer::port() const { return port_; }

std::string LoopbackServer::accept_request()
{
    int lfd = lbs_fd(impl_);
    int cfd = ::accept(lfd, nullptr, nullptr);
    if (cfd < 0)
        throw std::runtime_error(std::string("accept: ") +
                                 std::strerror(errno));
    client_impl_ = lbs_box(cfd);

    // Read until end-of-headers; we only need the first line in
    // practice.  Cap at 16 KB to bound memory for pathological
    // clients.
    std::string buf;
    char tmp[4096];
    while (buf.find("\r\n\r\n") == std::string::npos && buf.size() < 16384) {
        ssize_t n = ::read(cfd, tmp, sizeof(tmp));
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("read: ") +
                                     std::strerror(errno));
        }
        if (n == 0) break;
        buf.append(tmp, size_t(n));
    }

    // Extract "METHOD target HTTP/..." from the first line.
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
    int cfd = lbs_fd(client_impl_);
    if (cfd < 0)
        throw std::runtime_error("respond() before accept_request()");
    std::ostringstream resp;
    resp << "HTTP/1.1 200 OK\r\n"
         << "Content-Type: text/html; charset=utf-8\r\n"
         << "Content-Length: " << html.size() << "\r\n"
         << "Connection: close\r\n\r\n"
         << html;
    std::string s = resp.str();
    const char *p = s.data();
    size_t remaining = s.size();
    while (remaining > 0) {
        ssize_t n = ::write(cfd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error(std::string("write: ") +
                                     std::strerror(errno));
        }
        p += n;
        remaining -= size_t(n);
    }
    ::close(cfd);
    client_impl_ = nullptr;
}

void launch_browser(const std::string &url)
{
    // Prefer xdg-open (Linux/BSD) and open (macOS).  fork + execvp so
    // the browser runs asynchronously and we don't block on it.
    pid_t pid = ::fork();
    if (pid < 0)
        throw std::runtime_error(std::string("fork: ") +
                                 std::strerror(errno));
    if (pid == 0) {
        // Child.  Try xdg-open then open.  exec* returns only on error.
        const char *openers[] = { "xdg-open", "open", nullptr };
        for (int i = 0; openers[i]; i++) {
            char *argv[] = {
                const_cast<char *>(openers[i]),
                const_cast<char *>(url.c_str()),
                nullptr
            };
            ::execvp(argv[0], argv);
        }
        _exit(127);
    }
    // Parent: reap on next waitpid non-blocking attempt later;
    // SIGCHLD default is fine.  Don't block.
    (void)pid;
}

std::string config_dir()
{
    std::string base;
    if (const char *xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg) {
        base = xdg;
    } else if (const char *home = std::getenv("HOME"); home && *home) {
        base = std::string(home) + "/.config";
    } else {
        throw std::runtime_error(
            "cannot determine config dir: neither XDG_CONFIG_HOME nor HOME set");
    }
    // Ensure base exists (don't clobber if it already does).
    ::mkdir(base.c_str(), 0700);
    std::string dir = base + "/aas-sign";
    if (::mkdir(dir.c_str(), 0700) < 0 && errno != EEXIST)
        throw std::runtime_error(std::string("mkdir ") + dir + ": " +
                                 std::strerror(errno));
    return dir;
}

}  // namespace platform

// --- Entry point ---

// POSIX argv is UTF-8 under any modern locale.  Forward as-is.
// libFuzzer harnesses provide their own main(), so skip this one when
// AAS_SIGN_NO_MAIN is defined (set by cmake/Fuzzing.cmake).
#ifndef AAS_SIGN_NO_MAIN
int main(int argc, char **argv)
{
    return aas_sign_main(argc, argv);
}
#endif
