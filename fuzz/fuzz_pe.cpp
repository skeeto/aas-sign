// libFuzzer harness for the PE parser.  PeFile takes a path, so the
// harness writes each input to a reusable per-process tempfile and
// hands that path over.  Calls authenticode_hash() if the constructor
// succeeds, since that path walks the whole file with its own bounds
// arithmetic.

#include "pe.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <string>
#include <unistd.h>
#include <fcntl.h>

namespace {

std::string tmp_path()
{
    // One file per fuzz process, reused across iterations.  Leaks on
    // crash, but the fuzz runner restarts and /tmp gets cleaned.
    static std::string p = [] {
        std::string s = "/tmp/aas-sign-fuzz-" +
                        std::to_string(::getpid()) + ".bin";
        return s;
    }();
    return p;
}

bool write_input(const std::string &path, const uint8_t *data, size_t size)
{
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;
    const uint8_t *p = data;
    size_t left = size;
    while (left > 0) {
        ssize_t n = ::write(fd, p, left);
        if (n <= 0) { ::close(fd); return false; }
        p += n;
        left -= size_t(n);
    }
    ::close(fd);
    return true;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Cap input size -- libFuzzer's default max_len is already bounded,
    // but huge inputs here just slow the corpus without adding coverage.
    if (size > 256 * 1024) return 0;

    std::string path = tmp_path();
    if (!write_input(path, data, size)) return 0;

    try {
        PeFile pe(path);
        (void)pe.authenticode_hash();
    } catch (const std::exception &) {
        // Expected for non-PE / malformed / truncated inputs.
    }
    return 0;
}
