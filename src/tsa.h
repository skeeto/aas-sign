#ifndef TSA_H
#define TSA_H

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

#endif
