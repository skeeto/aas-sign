// libFuzzer harness for x509_cert_id(): walks a DER X.509 cert to
// extract issuer Name and serial INTEGER -- the CMS SignerInfo inputs.

#include "x509.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    try {
        auto id = x509_cert_id(data, size);
        (void)id.issuer_raw.size();
        (void)id.serial_raw.size();
    } catch (const std::exception &) {
        // Expected for malformed input.
    }
    return 0;
}
