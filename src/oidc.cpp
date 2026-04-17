#include "oidc.hpp"
#include "sha256.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <cstdlib>
#include <stdexcept>

using json = nlohmann::json;

OidcRuntime oidc_runtime()
{
    OidcRuntime r;
    if (const char *u = std::getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
        r.request_url = u;
    if (const char *t = std::getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
        r.request_token = t;
    return r;
}

// Percent-encode per RFC 3986 "unreserved"; used for the form body fields
// of the token exchange (some values -- the JWT especially -- contain
// characters like '.', '_', '-', '+', '/' that are mostly fine but the
// safe path is to encode everything not in [A-Za-z0-9._~-]).
static std::string url_encode(const std::string &s)
{
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size());
    for (char ch : s) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(char(c));
        } else {
            out.push_back('%');
            out.push_back(hex[(c >> 4) & 0xF]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

std::string oidc_fetch_azure_token(const OidcRuntime &r,
                                   const std::string &client_id,
                                   const std::string &tenant_id)
{
    if (r.request_url.empty() || r.request_token.empty())
        throw std::runtime_error(
            "OIDC requested but ACTIONS_ID_TOKEN_REQUEST_URL/"
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN are not set.  This flow only "
            "works inside a GitHub Actions runner with id-token: write "
            "permission.  On a laptop, use --token or $AZURE_ACCESS_TOKEN.");

    // Step 1: ask GitHub to mint an OIDC JWT for this workflow run.
    std::string mint_url = r.request_url;
    mint_url += (mint_url.find('?') == std::string::npos ? '?' : '&');
    mint_url += "audience=api%3A%2F%2FAzureADTokenExchange";
    auto github = platform::https_get_url(mint_url, r.request_token);
    if (github.status != 200)
        throw std::runtime_error("GitHub OIDC mint failed (HTTP " +
                                 std::to_string(github.status) + "): " +
                                 github.body);
    std::string jwt;
    try {
        jwt = json::parse(github.body).value("value", "");
    } catch (const std::exception &e) {
        throw std::runtime_error(
            std::string("GitHub OIDC response not JSON: ") + e.what());
    }
    if (jwt.empty())
        throw std::runtime_error(
            "GitHub OIDC response missing `value' field");

    // Step 2: exchange the JWT for an Azure access token.
    std::string form;
    auto add = [&](const char *k, const std::string &v) {
        if (!form.empty()) form += '&';
        form += k;
        form += '=';
        form += url_encode(v);
    };
    add("client_id",             client_id);
    add("scope",                 "https://codesigning.azure.net/.default");
    add("client_assertion_type",
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    add("client_assertion",      jwt);
    add("grant_type",            "client_credentials");

    std::string az_url = "https://login.microsoftonline.com/" + tenant_id +
                         "/oauth2/v2.0/token";
    auto az = platform::https_post_url(
        az_url, "application/x-www-form-urlencoded", form);
    if (az.status != 200)
        throw std::runtime_error("Azure token exchange failed (HTTP " +
                                 std::to_string(az.status) + "): " +
                                 az.body);
    std::string token;
    try {
        token = json::parse(az.body).value("access_token", "");
    } catch (const std::exception &e) {
        throw std::runtime_error(
            std::string("Azure token response not JSON: ") + e.what());
    }
    if (token.empty())
        throw std::runtime_error(
            "Azure token response missing `access_token' field");
    return token;
}
