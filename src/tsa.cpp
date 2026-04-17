#include "tsa.h"
#include "der.h"
#include "sha256.h"
#include "x509.h"

#include <chrono>
#include <random>
#include <stdexcept>

// Parse "http://host[:port]/path" into components.  Only plain HTTP is
// supported; TSAs don't rely on TLS for integrity.
static void parse_url(const std::string &url, std::string &host, int &port,
                      std::string &path)
{
    const std::string scheme = "http://";
    if (url.compare(0, scheme.size(), scheme) != 0)
        throw std::runtime_error("TSA URL must use http:// scheme: " + url);

    size_t host_start = scheme.size();
    size_t path_start = url.find('/', host_start);
    std::string hostport = (path_start == std::string::npos)
        ? url.substr(host_start)
        : url.substr(host_start, path_start - host_start);
    path = (path_start == std::string::npos) ? "/" : url.substr(path_start);

    size_t colon = hostport.find(':');
    if (colon == std::string::npos) {
        host = hostport;
        port = 80;
    } else {
        host = hostport.substr(0, colon);
        port = std::stoi(hostport.substr(colon + 1));
    }
}

// Build a DER-encoded TimeStampReq per RFC 3161.
static Bytes build_tsp_request(const std::array<uint8_t, 32> &hash,
                               int64_t nonce)
{
    //  version        INTEGER  { v1(1) }
    auto version = der_integer(1);

    //  messageImprint MessageImprint ::= SEQUENCE {
    //      hashAlgorithm   AlgorithmIdentifier,
    //      hashedMessage   OCTET STRING
    //  }
    auto sha256_oid = der_oid("2.16.840.1.101.3.4.2.1");
    auto null_params = der_null();
    auto hash_alg = der_sequence({&sha256_oid, &null_params});
    auto hashed = der_octet_string(hash.data(), hash.size());
    auto imprint = der_sequence({&hash_alg, &hashed});

    //  nonce          INTEGER OPTIONAL,
    auto nonce_int = der_integer(nonce);

    //  certReq        BOOLEAN DEFAULT FALSE,
    auto cert_req = der_boolean(true);

    return der_sequence({&version, &imprint, &nonce_int, &cert_req});
}

// Parse a DER-encoded TimeStampResp.  Returns the raw DER bytes of the
// TimeStampToken ContentInfo on success; throws on any failure status or
// parse error.
static Bytes extract_token(const uint8_t *data, size_t len)
{
    //  TimeStampResp ::= SEQUENCE {
    //      status          PKIStatusInfo,
    //      timeStampToken  TimeStampToken OPTIONAL
    //  }
    auto outer = der_read_tlv(data, len);
    if ((outer.tag & 0x1f) != 0x10)
        throw std::runtime_error("TSA response: expected outer SEQUENCE");

    //  PKIStatusInfo ::= SEQUENCE { status PKIStatus, ... }
    auto status_info = der_read_tlv(outer.content, outer.content_len);
    if ((status_info.tag & 0x1f) != 0x10)
        throw std::runtime_error("TSA response: expected PKIStatusInfo SEQUENCE");

    auto status_int = der_read_tlv(status_info.content,
                                   status_info.content_len);
    if (status_int.tag != 0x02 || status_int.content_len < 1)
        throw std::runtime_error("TSA response: expected status INTEGER");

    int status = 0;
    for (size_t i = 0; i < status_int.content_len; i++)
        status = (status << 8) | status_int.content[i];
    // PKIStatus: 0=granted, 1=grantedWithMods, others are errors.
    if (status != 0 && status != 1)
        throw std::runtime_error("TSA refused timestamp (PKIStatus " +
                                 std::to_string(status) + ")");

    // The timeStampToken follows PKIStatusInfo at the same level.
    const uint8_t *p = outer.content + status_info.total_len;
    size_t remaining = outer.content_len - status_info.total_len;
    if (remaining == 0)
        throw std::runtime_error("TSA response: no TimeStampToken present");

    auto token = der_read_tlv(p, remaining);
    if ((token.tag & 0x1f) != 0x10)
        throw std::runtime_error("TSA response: TimeStampToken is not a SEQUENCE");
    return Bytes(p, p + token.total_len);
}

std::vector<uint8_t> tsa_timestamp(const std::string &url,
                                   const std::vector<uint8_t> &signature)
{
    std::string host, path;
    int port = 80;
    parse_url(url, host, port, path);

    // messageImprint is SHA-256 of the RSA signature bytes (the contents of
    // the SignerInfo signature OCTET STRING, not the OCTET STRING itself).
    auto imprint_hash = platform::sha256(signature.data(), signature.size());

    // Random 63-bit nonce (positive to avoid a spurious leading 0x00 in the
    // DER INTEGER encoding; our der_integer handles it either way).
    std::random_device rd;
    std::mt19937_64 gen(rd());
    int64_t nonce =
        int64_t(gen() & 0x7fffffffffffffffULL);

    auto req = build_tsp_request(imprint_hash, nonce);

    auto resp = platform::http_post_binary(host, port, path,
                                           "application/timestamp-query",
                                           "application/timestamp-reply",
                                           req);
    if (resp.status != 200)
        throw std::runtime_error("TSA HTTP error: " +
                                 std::to_string(resp.status));
    if (resp.body.empty())
        throw std::runtime_error("TSA returned empty response");

    return extract_token(
        reinterpret_cast<const uint8_t *>(resp.body.data()),
        resp.body.size());
}
