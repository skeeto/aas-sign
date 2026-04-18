#include "azure.hpp"
#include "base64.hpp"
#include "platform.hpp"

#include <nlohmann/json.hpp>
#include <chrono>
#include <thread>
#include <stdexcept>

using json = nlohmann::json;

// Accept either a bare hostname or a full URL for the endpoint.
// Users commonly copy-paste a value like `https://eus.codesigning.azure.net/`
// from the Azure portal; strip the scheme and any trailing path so the
// underlying HTTPS client gets just the hostname it expects.
static std::string endpoint_host(std::string s)
{
    auto scheme = s.find("://");
    if (scheme != std::string::npos)
        s.erase(0, scheme + 3);
    auto slash = s.find('/');
    if (slash != std::string::npos)
        s.erase(slash);
    return s;
}

AzureSignResult azure_sign(const std::string &endpoint,
                           const std::string &account,
                           const std::string &profile,
                           const std::string &token,
                           const uint8_t *digest, size_t digest_len)
{
    const std::string host = endpoint_host(endpoint);
    std::string path = "/codesigningaccounts/" + account +
                       "/certificateprofiles/" + profile +
                       "/sign?api-version=2022-06-15-preview";

    std::string b64_digest = base64_encode(digest, digest_len);
    json req_body;
    req_body["signatureAlgorithm"] = "RS256";
    req_body["digest"] = b64_digest;

    auto resp = platform::https_post(host, path, token,
                                     req_body.dump());
    if (resp.status != 200 && resp.status != 202)
        throw std::runtime_error("Azure sign POST failed (HTTP " +
                                 std::to_string(resp.status) + "): " +
                                 resp.body);

    auto body = json::parse(resp.body);
    std::string operation_id = body.value("operationId", "");
    std::string status = body.value("status", "");

    // Poll until completed.
    std::string poll_path = "/codesigningaccounts/" + account +
                            "/certificateprofiles/" + profile +
                            "/sign/" + operation_id +
                            "?api-version=2022-06-15-preview";

    auto start = std::chrono::steady_clock::now();
    int i = 0;
    while (status == "InProgress") {
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > std::chrono::seconds(60))
            throw std::runtime_error("Azure signing operation " +
                                     operation_id + " timed out");

        int delay = std::min(1000, 50 + 10 * i++);
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));

        auto poll = platform::https_get(host, poll_path, token);
        if (poll.status != 200)
            throw std::runtime_error("Azure sign poll failed (HTTP " +
                                     std::to_string(poll.status) + "): " +
                                     poll.body);
        body = json::parse(poll.body);
        status = body.value("status", "");
    }

    if (status != "Succeeded")
        throw std::runtime_error("Azure signing failed: " + status);

    AzureSignResult result;
    result.signature = base64_decode(body["signature"].get<std::string>());

    // signingCertificate is double-encoded: the JSON value is base64-encoded
    // PEM text, which itself is base64-encoded DER.  Decode both layers.
    auto pem_bytes = base64_decode(
        body["signingCertificate"].get<std::string>());
    std::string pem_text(pem_bytes.begin(), pem_bytes.end());
    result.cert_chain_der = base64_mime_decode(pem_text);

    return result;
}
