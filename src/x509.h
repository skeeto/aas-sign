#pragma once

#include <cstdint>
#include <vector>

// Minimal DER TLV reader.
struct TlvView {
    uint8_t tag;
    const uint8_t *content;
    size_t content_len;
    size_t total_len;  // tag + length + content
};

TlvView der_read_tlv(const uint8_t *data, size_t len);

// Parsed fields from an X.509 certificate needed for CMS SignerInfo.
struct CertId {
    std::vector<uint8_t> issuer_raw;  // raw DER of issuer Name SEQUENCE
    std::vector<uint8_t> serial_raw;  // raw DER of serial INTEGER
};

// Extract issuer and serial from a single DER-encoded X.509 certificate.
CertId x509_cert_id(const uint8_t *cert_der, size_t cert_len);

// Split a buffer of concatenated DER certificates into individual certs.
std::vector<std::vector<uint8_t>> x509_split_certs(const uint8_t *data,
                                                    size_t len);

