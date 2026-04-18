// libFuzzer harness for tsa_parse_response(): parses an RFC 3161
// TimeStampResp blob returned by the TSA and extracts the inner
// TimeStampToken.  Attackers who control the timestamp authority (or
// can MITM the plain-HTTP TSA connection) feed this function.

#include "tsa.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    try {
        auto token = tsa_parse_response(data, size);
        (void)token.size();
    } catch (const std::exception &) {
        // Expected for malformed or error-status responses.
    }
    return 0;
}
