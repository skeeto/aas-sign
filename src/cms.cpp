#include "cms.hpp"
#include "der.hpp"
#include "sha256.hpp"
#include "x509.hpp"
#include <stdexcept>

// Well-known OIDs.
static Bytes oid_signed_data()       { return der_oid("1.2.840.113549.1.7.2"); }
static Bytes oid_spc_indirect_data() { return der_oid("1.3.6.1.4.1.311.2.1.4"); }
static Bytes oid_spc_pe_image_data() { return der_oid("1.3.6.1.4.1.311.2.1.15"); }
static Bytes oid_spc_statement_type(){ return der_oid("1.3.6.1.4.1.311.2.1.11"); }
static Bytes oid_spc_individual()    { return der_oid("1.3.6.1.4.1.311.2.1.21"); }
static Bytes oid_sha256()            { return der_oid("2.16.840.1.101.3.4.2.1"); }
static Bytes oid_rsa_encryption()    { return der_oid("1.2.840.113549.1.1.1"); }
static Bytes oid_content_type()      { return der_oid("1.2.840.113549.1.9.3"); }
static Bytes oid_message_digest()    { return der_oid("1.2.840.113549.1.9.4"); }
static Bytes oid_spc_rfc3161()       { return der_oid("1.3.6.1.4.1.311.3.3.1"); }

// SHA-256 AlgorithmIdentifier: SEQUENCE { OID sha-256, NULL }.
static Bytes sha256_alg_id()
{
    auto oid = oid_sha256();
    auto null = der_null();
    return der_sequence({&oid, &null});
}

// SpcPeImageData: fixed bytes for flags=empty, file=SpcLink(SpcString("")).
// SEQUENCE { BIT STRING 03 01 00, [0] EXPLICIT { [2] EXPLICIT { [0] IMPLICIT "" } } }
static Bytes spc_pe_image_data()
{
    // SpcString: [0] IMPLICIT BMPString "" -> 80 00
    // SpcLink file: [2] EXPLICIT wrapping SpcString -> A2 02 80 00
    // SpcPeImageData file: [0] EXPLICIT wrapper -> A0 04 A2 02 80 00
    // BIT STRING with empty content: 03 01 00
    static const uint8_t data[] = {
        0x30, 0x09,
        0x03, 0x01, 0x00,
        0xa0, 0x04, 0xa2, 0x02, 0x80, 0x00
    };
    return Bytes(data, data + sizeof(data));
}

// Build SpcIndirectDataContent.
static Bytes build_spc_indirect_data(const std::array<uint8_t, 32> &pe_hash)
{
    // SpcAttributeTypeAndOptionalValue: SEQUENCE { OID, SpcPeImageData }
    auto pe_image_oid = oid_spc_pe_image_data();
    auto pe_image = spc_pe_image_data();
    auto spc_attr = der_sequence({&pe_image_oid, &pe_image});

    // DigestInfo: SEQUENCE { AlgorithmIdentifier, OCTET STRING hash }
    auto alg_id = sha256_alg_id();
    auto hash_octets = der_octet_string(pe_hash.data(), pe_hash.size());
    auto digest_info = der_sequence({&alg_id, &hash_octets});

    return der_sequence({&spc_attr, &digest_info});
}

// Build the authenticated attributes SET (tag 0x31).
static Bytes build_auth_attrs(const Bytes &spc_indirect_data)
{
    // Authenticode messageDigest is SHA-256 of the CONTENT of the
    // SpcIndirectDataContent SEQUENCE, not the SEQUENCE itself.  Skip the
    // 2-byte DER header (tag 0x30 + short-form length; our content is always
    // < 128 bytes so short-form applies).
    auto content_hash = platform::sha256(spc_indirect_data.data() + 2,
                                         spc_indirect_data.size() - 2);

    // Attribute 1: contentType = SPC_INDIRECT_DATA
    auto ct_oid = oid_content_type();
    auto ct_val_oid = oid_spc_indirect_data();
    auto ct_val = der_set({&ct_val_oid});
    auto attr_content_type = der_sequence({&ct_oid, &ct_val});

    // Attribute 2: messageDigest = SHA256(SpcIndirectDataContent)
    auto md_oid = oid_message_digest();
    auto md_val_octets = der_octet_string(content_hash.data(),
                                          content_hash.size());
    auto md_val = der_set({&md_val_octets});
    auto attr_msg_digest = der_sequence({&md_oid, &md_val});

    // Attribute 3: SPC_STATEMENT_TYPE = { SPC_INDIVIDUAL_SP_KEY_PURPOSE }
    auto st_oid = oid_spc_statement_type();
    auto st_ind_oid = oid_spc_individual();
    auto st_ind_seq = der_sequence({&st_ind_oid});
    auto st_val = der_set({&st_ind_seq});
    auto attr_statement = der_sequence({&st_oid, &st_val});

    return der_set({&attr_content_type, &attr_msg_digest, &attr_statement});
}

std::array<uint8_t, 32> cms_auth_attrs_hash(
    const std::array<uint8_t, 32> &pe_hash)
{
    auto spc_idc = build_spc_indirect_data(pe_hash);
    auto auth_attrs = build_auth_attrs(spc_idc);
    return platform::sha256(auth_attrs.data(), auth_attrs.size());
}

std::vector<uint8_t> cms_build_authenticode(
    const std::array<uint8_t, 32> &pe_hash,
    const std::vector<uint8_t> &signature,
    const std::vector<uint8_t> &certs_der,
    const std::vector<uint8_t> &timestamp_token_der)
{
    // Parse signing cert to get issuer + serial.
    auto certs = x509_split_certs(certs_der.data(), certs_der.size());
    if (certs.empty())
        throw std::runtime_error("no certificates in chain");
    auto cert_id = x509_cert_id(certs[0].data(), certs[0].size());

    // Build SpcIndirectDataContent.
    auto spc_idc = build_spc_indirect_data(pe_hash);

    // Build authenticated attributes (as SET, tag 0x31).
    auto auth_attrs_set = build_auth_attrs(spc_idc);

    // --- SignerInfo ---

    auto si_version = der_integer(1);

    // IssuerAndSerialNumber.
    Bytes issuer_raw(cert_id.issuer_raw);
    Bytes serial_raw(cert_id.serial_raw);
    auto sid = der_sequence({&issuer_raw, &serial_raw});

    auto si_digest_alg = sha256_alg_id();

    // Authenticated attrs with IMPLICIT [0] tag (0xA0 replaces 0x31).
    auto si_auth_attrs = der_implicit(0, true, auth_attrs_set);

    // signatureAlgorithm: rsaEncryption with NULL.
    auto rsa_oid = oid_rsa_encryption();
    auto rsa_null = der_null();
    auto si_sig_alg = der_sequence({&rsa_oid, &rsa_null});

    auto si_signature = der_octet_string(signature.data(), signature.size());

    // Optional unsignedAttrs [1] IMPLICIT SET containing the RFC 3161
    // timestamp token under OID 1.3.6.1.4.1.311.3.3.1.
    Bytes si_unsigned_attrs;
    if (!timestamp_token_der.empty()) {
        auto ts_oid = oid_spc_rfc3161();
        auto ts_token = der_raw(timestamp_token_der.data(),
                                timestamp_token_der.size());
        auto ts_val = der_set({&ts_token});
        auto ts_attr = der_sequence({&ts_oid, &ts_val});
        auto unsigned_set = der_set({&ts_attr});
        si_unsigned_attrs = der_implicit(1, true, unsigned_set);
    }

    Bytes signer_info;
    if (si_unsigned_attrs.empty()) {
        signer_info = der_sequence({&si_version, &sid, &si_digest_alg,
                                    &si_auth_attrs, &si_sig_alg,
                                    &si_signature});
    } else {
        signer_info = der_sequence({&si_version, &sid, &si_digest_alg,
                                    &si_auth_attrs, &si_sig_alg,
                                    &si_signature, &si_unsigned_attrs});
    }

    // --- SignedData ---

    auto sd_version = der_integer(1);

    auto sd_digest_alg = sha256_alg_id();
    auto sd_digest_algs = der_set({&sd_digest_alg});

    // encapContentInfo: SEQUENCE { OID SPC_INDIRECT_DATA, [0] EXPLICIT content }
    auto eciOid = oid_spc_indirect_data();
    auto eciContent = der_explicit(0, spc_idc);
    auto encap_content = der_sequence({&eciOid, &eciContent});

    // Certificates [0] IMPLICIT: concatenate individual cert DER blobs.
    Bytes all_certs;
    for (auto &c : certs)
        all_certs.insert(all_certs.end(), c.begin(), c.end());
    auto certs_wrapped = der_wrap(0xa0, all_certs.data(), all_certs.size());

    auto signer_infos = der_set({&signer_info});

    auto signed_data = der_sequence({&sd_version, &sd_digest_algs,
                                     &encap_content, &certs_wrapped,
                                     &signer_infos});

    // --- Outer ContentInfo ---

    auto ci_oid = oid_signed_data();
    auto ci_content = der_explicit(0, signed_data);

    return der_sequence({&ci_oid, &ci_content});
}
