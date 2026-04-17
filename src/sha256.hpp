#pragma once

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

// 64-bit-offset file I/O with checked error handling.  Paths are UTF-8
// on all platforms (transcoded to UTF-16 for Windows CreateFileW).
// Every method throws std::runtime_error on error or short transfer.
class File {
public:
    // Open an existing file for read+write.  Throws if the file does
    // not exist or cannot be opened.
    explicit File(const std::string &utf8_path);
    ~File();
    File(const File &) = delete;
    File &operator=(const File &) = delete;

    uint64_t size();
    void read_at(uint64_t offset, void *buf, size_t len);
    void write_at(uint64_t offset, const void *buf, size_t len);
    void truncate(uint64_t new_size);
    void flush();

private:
    std::string path_;  // kept for error messages
    void *impl_;        // HANDLE on Windows, (void *)(intptr_t) fd on POSIX
};

// Create or overwrite a file and write exactly `len` bytes.  Throws on
// any error.  The UTF-8 path is transcoded as needed.
void write_whole_file(const std::string &utf8_path,
                      const uint8_t *data, size_t len);

}  // namespace platform

