#include "x509.hpp"
#include "narrow.hpp"
#include <cstring>
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
        if (nbytes == 0 || nbytes > 4 || pos + narrow<size_t>(nbytes) > len)
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

// signedData OID: 1.2.840.113549.1.7.2
static const uint8_t oid_signed_data[] = {
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02
};

// Check if data is a CMS/PKCS#7 ContentInfo wrapping SignedData.
// If so, extract certificates from the SignedData certificates field.
static bool try_extract_cms_certs(const uint8_t *data, size_t len,
                                  std::vector<std::vector<uint8_t>> &out)
{
    if (len < 20) return false;

    // ContentInfo SEQUENCE
    auto ci = der_read_tlv(data, len);
    if (ci.tag != 0x30) return false;

    // First element should be OID
    auto oid = der_read_tlv(ci.content, ci.content_len);
    if (oid.tag != 0x06 || oid.content_len != sizeof(oid_signed_data))
        return false;
    if (memcmp(oid.content, oid_signed_data, sizeof(oid_signed_data)) != 0)
        return false;

    // [0] EXPLICIT content
    const uint8_t *p = ci.content + oid.total_len;
    size_t remaining = ci.content_len - oid.total_len;
    auto explicit0 = der_read_tlv(p, remaining);
    if (explicit0.tag != 0xa0) return false;

    // SignedData SEQUENCE
    auto sd = der_read_tlv(explicit0.content, explicit0.content_len);
    if (sd.tag != 0x30) return false;

    // Walk SignedData fields looking for certificates [0] IMPLICIT
    p = sd.content;
    remaining = sd.content_len;
    while (remaining > 0) {
        auto field = der_read_tlv(p, remaining);
        if (field.tag == 0xa0) {
            // certificates field — split individual certs from within
            const uint8_t *cp = field.content;
            size_t cr = field.content_len;
            while (cr > 0) {
                auto cert = der_read_tlv(cp, cr);
                out.emplace_back(cp, cp + cert.total_len);
                cp += cert.total_len;
                cr -= cert.total_len;
            }
            return true;
        }
        p += field.total_len;
        remaining -= field.total_len;
    }

    return false;
}

std::vector<std::vector<uint8_t>> x509_split_certs(const uint8_t *data,
                                                    size_t len)
{
    std::vector<std::vector<uint8_t>> certs;

    // Try CMS/PKCS#7 format first.
    if (try_extract_cms_certs(data, len, certs))
        return certs;

    // Otherwise treat as raw concatenated DER certificates.
    size_t pos = 0;
    while (pos < len) {
        auto tlv = der_read_tlv(data + pos, len - pos);
        certs.emplace_back(data + pos, data + pos + tlv.total_len);
        pos += tlv.total_len;
    }
    return certs;
}
