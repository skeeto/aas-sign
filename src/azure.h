#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct AzureSignResult {
    std::vector<uint8_t> signature;            // raw RSA signature bytes
    std::vector<uint8_t> cert_chain_der;       // concatenated DER certs
};

// Sign a digest via Azure Trusted Signing.
// The digest should be the SHA-256 hash of the authenticated attributes.
AzureSignResult azure_sign(const std::string &endpoint,
                           const std::string &account,
                           const std::string &profile,
                           const std::string &token,
                           const uint8_t *digest, size_t digest_len);

