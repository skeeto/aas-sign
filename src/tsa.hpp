#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Request an RFC 3161 timestamp for the given RSA signature bytes.
// Returns the raw DER bytes of the TimeStampToken (a CMS ContentInfo
// SEQUENCE), suitable for embedding as the value of an
// szOID_RFC3161_counterSign (1.3.6.1.4.1.311.3.3.1) unsigned attribute in
// the SignerInfo.
//
// url: full URL of the TSA, e.g. http://timestamp.acs.microsoft.com/timestamping/RFC3161
std::vector<uint8_t> tsa_timestamp(const std::string &url,
                                   const std::vector<uint8_t> &signature);

// Parse a DER-encoded RFC 3161 TimeStampResp and return the raw DER
// bytes of the enclosed TimeStampToken.  Throws std::runtime_error on
// malformed input or a non-granted PKIStatus.  Exposed for fuzzing;
// production callers go through tsa_timestamp().
std::vector<uint8_t> tsa_parse_response(const uint8_t *data, size_t len);

