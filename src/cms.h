#ifndef CMS_H
#define CMS_H

#include <array>
#include <cstdint>
#include <vector>

// Build the complete CMS ContentInfo (Authenticode SignedData) for a PE
// signature, ready to be wrapped in a WIN_CERTIFICATE and injected.
//
// pe_hash:        32-byte Authenticode SHA-256 digest of the PE
// signature:      raw RSA signature bytes from Azure
// certs_der:      concatenated DER-encoded certificate chain
// Compute SHA-256(DER(authenticated_attributes_as_SET)).
// This is the digest that Azure will sign.
std::array<uint8_t, 32> cms_auth_attrs_hash(
    const std::array<uint8_t, 32> &pe_hash);

// Build the complete CMS ContentInfo (Authenticode SignedData) for a PE
// signature, ready to be wrapped in a WIN_CERTIFICATE and injected.
std::vector<uint8_t> cms_build_authenticode(
    const std::array<uint8_t, 32> &pe_hash,
    const std::vector<uint8_t> &signature,
    const std::vector<uint8_t> &certs_der);

#endif
