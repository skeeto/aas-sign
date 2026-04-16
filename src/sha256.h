#ifndef SHA256_H
#define SHA256_H

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace platform {

struct Sha256 {
    Sha256();
    ~Sha256();
    Sha256(const Sha256 &) = delete;
    Sha256 &operator=(const Sha256 &) = delete;
    void update(const uint8_t *data, size_t len);
    std::array<uint8_t, 32> finish();
    void *ctx;
};

std::array<uint8_t, 32> sha256(const uint8_t *data, size_t len);

struct HttpResponse {
    int status;
    std::string body;
};

HttpResponse https_post(const std::string &host, const std::string &path,
                        const std::string &bearer_token,
                        const std::string &json_body);

HttpResponse https_get(const std::string &host, const std::string &path,
                       const std::string &bearer_token);

// Plain HTTP POST with a binary body.  Used for RFC 3161 timestamping where
// integrity is guaranteed by the TSA's own signature rather than TLS.
HttpResponse http_post_binary(const std::string &host, int port,
                              const std::string &path,
                              const std::string &content_type,
                              const std::string &accept,
                              const std::vector<uint8_t> &body);

}  // namespace platform

#endif
