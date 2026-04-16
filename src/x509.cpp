#include "x509.h"
#include <stdexcept>

TlvView der_read_tlv(const uint8_t *data, size_t len)
{
    if (len < 2)
        throw std::runtime_error("truncated DER TLV");

    TlvView v;
    v.tag = data[0];
    size_t pos = 1;

    if (data[pos] < 0x80) {
        v.content_len = data[pos];
        pos++;
    } else {
        int nbytes = data[pos] & 0x7f;
        pos++;
        if (nbytes == 0 || nbytes > 4 || pos + nbytes > len)
            throw std::runtime_error("invalid DER length");
        v.content_len = 0;
        for (int i = 0; i < nbytes; i++)
            v.content_len = (v.content_len << 8) | data[pos++];
    }

    if (pos + v.content_len > len)
        throw std::runtime_error("DER content exceeds buffer");

    v.content = data + pos;
    v.total_len = pos + v.content_len;
    return v;
}

CertId x509_cert_id(const uint8_t *cert_der, size_t cert_len)
{
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    auto cert = der_read_tlv(cert_der, cert_len);
    if ((cert.tag & 0x1f) != 0x10)
        throw std::runtime_error("expected SEQUENCE for Certificate");

    // tbsCertificate ::= SEQUENCE { version, serial, sigAlg, issuer, ... }
    auto tbs = der_read_tlv(cert.content, cert.content_len);
    if ((tbs.tag & 0x1f) != 0x10)
        throw std::runtime_error("expected SEQUENCE for TBSCertificate");

    const uint8_t *p = tbs.content;
    size_t remaining = tbs.content_len;

    // Skip version [0] EXPLICIT if present.
    auto elem = der_read_tlv(p, remaining);
    if (elem.tag == 0xa0) {
        p += elem.total_len;
        remaining -= elem.total_len;
        elem = der_read_tlv(p, remaining);
    }

    // serialNumber INTEGER -- capture raw TLV.
    CertId id;
    if (elem.tag != 0x02)
        throw std::runtime_error("expected INTEGER for serialNumber");
    id.serial_raw.assign(p, p + elem.total_len);
    p += elem.total_len;
    remaining -= elem.total_len;

    // Skip signature AlgorithmIdentifier SEQUENCE.
    elem = der_read_tlv(p, remaining);
    p += elem.total_len;
    remaining -= elem.total_len;

    // issuer Name SEQUENCE -- capture raw TLV.
    elem = der_read_tlv(p, remaining);
    if ((elem.tag & 0x1f) != 0x10)
        throw std::runtime_error("expected SEQUENCE for issuer");
    id.issuer_raw.assign(p, p + elem.total_len);

    return id;
}

std::vector<std::vector<uint8_t>> x509_split_certs(const uint8_t *data,
                                                    size_t len)
{
    std::vector<std::vector<uint8_t>> certs;
    size_t pos = 0;
    while (pos < len) {
        auto tlv = der_read_tlv(data + pos, len - pos);
        certs.emplace_back(data + pos, data + pos + tlv.total_len);
        pos += tlv.total_len;
    }
    return certs;
}
