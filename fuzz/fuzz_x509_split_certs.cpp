// libFuzzer harness for x509_split_certs(): splits a buffer of
// concatenated DER certs into individual cert blobs.

#include "x509.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    try {
        auto certs = x509_split_certs(data, size);
        (void)certs.size();
    } catch (const std::exception &) {
        // Expected for malformed input.
    }
    return 0;
}
