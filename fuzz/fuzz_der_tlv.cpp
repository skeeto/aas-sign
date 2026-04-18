// libFuzzer harness for der_read_tlv(): the DER TLV primitive that
// underlies all our ASN.1 parsing.  Exercises the 1/2/3/4-byte length
// encodings and the short-form / long-form discriminator.

#include "x509.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    try {
        auto tlv = der_read_tlv(data, size);
        // Force the compiler to treat the parsed fields as live so
        // loads/stores aren't optimised away.
        (void)tlv.tag;
        (void)tlv.content;
        (void)tlv.content_len;
        (void)tlv.total_len;
    } catch (const std::exception &) {
        // Expected rejection path for malformed input.
    }
    return 0;
}
