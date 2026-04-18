#include "auth_laptop.hpp"
#include "base64.hpp"
#include "platform.hpp"
#include "urlenc.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>

using json = nlohmann::json;

namespace {

// ----- Small helpers ---------------------------------------------------

// 32 bytes of OS randomness for PKCE / state.
std::vector<uint8_t> random_bytes(size_t n)
{
    std::vector<uint8_t> out(n);
    std::random_device rd;
    // random_device produces unsigned int; pull in chunks of 4.
    for (size_t i = 0; i < n; i += 4) {
        uint32_t v = rd();
        for (size_t j = 0; j < 4 && i + j < n; j++)
            out[i + j] = uint8_t((v >> (8 * j)) & 0xff);
    }
    return out;
}

// Hex encode for the `state` parameter.
std::string hex_encode(const std::vector<uint8_t> &bytes)
{
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(hex[(b >> 4) & 0xF]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

// Parse the `?code=X&state=Y` part of an HTTP request target into a
// key->value map.  `target` begins with '/' and must contain a '?'.
std::map<std::string, std::string> parse_query(const std::string &target)
{
    std::map<std::string, std::string> q;
    auto qpos = target.find('?');
    if (qpos == std::string::npos) return q;
    std::string qs = target.substr(qpos + 1);
    size_t p = 0;
    while (p < qs.size()) {
        size_t amp = qs.find('&', p);
        if (amp == std::string::npos) amp = qs.size();
        std::string pair = qs.substr(p, amp - p);
        auto eq = pair.find('=');
        std::string k = (eq == std::string::npos) ? pair : pair.substr(0, eq);
        std::string v = (eq == std::string::npos) ? "" : pair.substr(eq + 1);
        // URL-decode the value.  Keys we expect are alphanumeric.
        std::string decoded;
        for (size_t i = 0; i < v.size(); i++) {
            if (v[i] == '+') {
                decoded.push_back(' ');
            } else if (v[i] == '%' && i + 2 < v.size()) {
                auto h = [](char c) {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    return 0;
                };
                decoded.push_back(char((h(v[i+1]) << 4) | h(v[i+2])));
                i += 2;
            } else {
                decoded.push_back(v[i]);
            }
        }
        q[k] = decoded;
        p = amp + 1;
    }
    return q;
}

// Form-encode a map of key=value pairs, percent-encoding each.
std::string form_encode(const std::vector<std::pair<std::string, std::string>> &pairs)
{
    std::string out;
    for (auto &kv : pairs) {
        if (!out.empty()) out.push_back('&');
        out += kv.first;
        out.push_back('=');
        out += url_encode(kv.second);
    }
    return out;
}

// Extract the JWT payload (middle segment) from an id_token and parse
// as JSON.  Returns an empty object on failure.
json decode_jwt_payload(const std::string &jwt)
{
    auto a = jwt.find('.');
    if (a == std::string::npos) return {};
    auto b = jwt.find('.', a + 1);
    if (b == std::string::npos) return {};
    std::string payload_b64 = jwt.substr(a + 1, b - a - 1);
    auto bytes = base64url_decode(payload_b64);
    try {
        return json::parse(bytes.begin(), bytes.end());
    } catch (...) {
        return {};
    }
}

// ----- Cache file I/O --------------------------------------------------

std::string cache_path()
{
    return platform::config_dir() + "/token-cache.json";
}

json read_cache()
{
    std::ifstream f(cache_path(), std::ios::binary);
    if (!f)
        return json();  // null if file doesn't exist
    try {
        json j;
        f >> j;
        return j;
    } catch (const std::exception &e) {
        throw std::runtime_error(
            std::string("cache file is corrupted (") + e.what() +
            "); run `aas-sign login` again");
    }
}

static void atomic_write_json(const std::string &path, const json &j)
{
    std::string body = j.dump(2);
    platform::atomic_write_private_file(
        path,
        reinterpret_cast<const uint8_t *>(body.data()),
        body.size());
}

void write_cache(const json &j)
{
    atomic_write_json(cache_path(), j);
}

void delete_cache()
{
    platform::remove_file(cache_path());
}

// Merge any non-empty signing defaults into config.json (preserving
// fields the caller didn't touch), and print a one-line note on the
// write.  No-op when all three are empty.  Shared by `login` and
// `config` subcommands.
void save_signing_defaults(const std::string &endpoint,
                           const std::string &account,
                           const std::string &profile)
{
    if (endpoint.empty() && account.empty() && profile.empty())
        return;
    std::string cfg_path = platform::config_dir() + "/config.json";
    json cfg;
    std::ifstream existing(cfg_path);
    if (existing) {
        try { existing >> cfg; } catch (...) { cfg = json::object(); }
    }
    if (!cfg.is_object()) cfg = json::object();
    if (!endpoint.empty()) cfg["endpoint"] = endpoint;
    if (!account.empty())  cfg["account"]  = account;
    if (!profile.empty())  cfg["profile"]  = profile;
    atomic_write_json(cfg_path, cfg);
    platform::write_stderr("Saved signing defaults to " + cfg_path + "\n");
}

// ----- Token endpoints -------------------------------------------------

constexpr const char SCOPE_SIGN[] =
    "https://codesigning.azure.net/.default";

std::string token_url(const std::string &tenant)
{
    return "https://login.microsoftonline.com/" + tenant +
           "/oauth2/v2.0/token";
}

}  // namespace

// ----- Login -----------------------------------------------------------

int login_main(int argc, char **argv)
{
    std::string tenant = AAS_SIGN_DEFAULT_TENANT;
    std::string client_id = AAS_SIGN_DEFAULT_CLIENT_ID;
    // Optional signing defaults -- if any are provided, they're written
    // to config.json after a successful login so that later `sign` runs
    // don't need them on the command line.
    std::string cfg_endpoint, cfg_account, cfg_profile;

    for (int i = 2; i < argc; i++) {  // argv[1] == "login"
        if (!strcmp(argv[i], "--tenant") && i + 1 < argc)
            tenant = argv[++i];
        else if (!strcmp(argv[i], "--client-id") && i + 1 < argc)
            client_id = argv[++i];
        else if (!strcmp(argv[i], "--endpoint") && i + 1 < argc)
            cfg_endpoint = argv[++i];
        else if (!strcmp(argv[i], "--account") && i + 1 < argc)
            cfg_account = argv[++i];
        else if (!strcmp(argv[i], "--profile") && i + 1 < argc)
            cfg_profile = argv[++i];
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            std::ostringstream os;
            os
                << "usage: aas-sign login [--tenant T] [--client-id C]\n"
                << "                      [--endpoint H] [--account N]"
                                                 " [--profile P]\n"
                << "\n"
                << "Open the system browser, sign in to Microsoft Entra, and\n"
                << "cache a refresh token at\n"
                << "    " << platform::config_dir() << "/token-cache.json\n"
                << "Subsequent `aas-sign sign` runs use the cached token\n"
                << "automatically until it's revoked or expires.\n"
                << "\n"
                << "  --tenant T     Azure tenant (default: the repo owner's).\n"
                << "  --client-id C  Override the baked-in aas-sign app ID.\n"
                << "\n"
                << "  --endpoint H, --account N, --profile P\n"
                << "                 If any of these is passed, it is saved\n"
                << "                 (merged) into config.json alongside the\n"
                << "                 token cache, becoming the default for\n"
                << "                 later `aas-sign sign` calls.\n";
            platform::write_stdout(os.str());
            return 0;
        }
        else {
            platform::write_stderr(
                std::string("aas-sign login: unknown option: ") +
                argv[i] + "\n");
            return 1;
        }
    }

    // PKCE: verifier = 32 random bytes, base64url.
    // challenge = base64url(SHA-256(verifier)).
    auto verifier_bytes = random_bytes(32);
    std::string verifier = base64url_encode(verifier_bytes.data(),
                                            verifier_bytes.size());
    auto challenge_hash = platform::sha256(
        reinterpret_cast<const uint8_t *>(verifier.data()),
        verifier.size());
    std::string challenge = base64url_encode(challenge_hash.data(),
                                             challenge_hash.size());

    auto state_bytes = random_bytes(16);
    std::string state = hex_encode(state_bytes);

    // Bind the loopback server first so we know our port.
    platform::LoopbackServer server;
    std::string redirect_uri = "http://localhost:" +
                               std::to_string(server.port());

    std::string authorize =
        "https://login.microsoftonline.com/" + tenant +
        "/oauth2/v2.0/authorize"
        "?client_id=" + url_encode(client_id) +
        "&response_type=code"
        "&redirect_uri=" + url_encode(redirect_uri) +
        "&response_mode=query"
        "&scope=" + url_encode(std::string(SCOPE_SIGN) +
                               " offline_access") +
        "&state=" + state +
        "&code_challenge=" + challenge +
        "&code_challenge_method=S256";

    {
        std::ostringstream os;
        os << "Opening browser to sign in...\n"
           << "If it doesn't open automatically, visit:\n  "
           << authorize << "\n";
        platform::write_stderr(os.str());
    }
    try {
        platform::launch_browser(authorize);
    } catch (const std::exception &e) {
        platform::write_stderr(std::string("(warning: ") + e.what() + ")\n");
    }

    // Wait for the redirect.
    std::string target = server.accept_request();
    auto q = parse_query(target);

    if (auto it = q.find("error"); it != q.end()) {
        std::string msg = "authorization failed: " + it->second;
        if (auto d = q.find("error_description"); d != q.end())
            msg += " -- " + d->second;
        server.respond("<!doctype html><meta charset=utf-8>"
                       "<p>aas-sign login failed. You can close this window.");
        platform::write_stderr(msg + "\n");
        return 1;
    }

    auto code_it = q.find("code");
    auto state_it = q.find("state");
    if (code_it == q.end() || state_it == q.end()) {
        server.respond("<!doctype html><meta charset=utf-8>"
                       "<p>Missing code or state. You can close this window.");
        platform::write_stderr("authorization response missing code/state\n");
        return 1;
    }
    if (state_it->second != state) {
        server.respond("<!doctype html><meta charset=utf-8>"
                       "<p>State mismatch. You can close this window.");
        platform::write_stderr("state mismatch: possible CSRF, aborting\n");
        return 1;
    }

    server.respond(
        "<!doctype html><meta charset=utf-8>"
        "<title>aas-sign</title>"
        "<h1>Signed in.</h1>"
        "<p>You can close this window.");

    // Exchange the code for tokens.
    std::string form = form_encode({
        {"client_id",     client_id},
        {"grant_type",    "authorization_code"},
        {"code",          code_it->second},
        {"redirect_uri",  redirect_uri},
        {"code_verifier", verifier},
        {"scope",         std::string(SCOPE_SIGN) + " offline_access"},
    });

    auto resp = platform::https_post_url(
        token_url(tenant), "application/x-www-form-urlencoded", form);
    if (resp.status != 200)
        throw std::runtime_error("token exchange failed (HTTP " +
                                 std::to_string(resp.status) + "): " +
                                 resp.body);

    json body = json::parse(resp.body);
    std::string refresh_token = body.value("refresh_token", "");
    std::string id_token = body.value("id_token", "");
    if (refresh_token.empty())
        throw std::runtime_error("no refresh_token in token response");

    // Extract identity info from the id_token for informational display.
    std::string username = "unknown";
    std::string tenant_id;
    std::string oid;
    if (!id_token.empty()) {
        json claims = decode_jwt_payload(id_token);
        if (claims.is_object()) {
            tenant_id = claims.value("tid", "");
            oid = claims.value("oid", "");
            username = claims.value("preferred_username", "");
            if (username.empty()) username = claims.value("upn", "");
            if (username.empty()) username = claims.value("email", "");
            if (username.empty()) username = "unknown";
        }
    }

    json cache;
    cache["version"]         = 1;
    cache["tenant_id"]       = tenant_id;
    cache["client_id"]       = client_id;
    cache["home_account_id"] = oid.empty() ? "" : oid + "." + tenant_id;
    cache["username"]        = username;
    cache["refresh_token"]   = refresh_token;
    write_cache(cache);

    {
        std::ostringstream os;
        os << "Logged in as " << username << ".\n"
           << "Cache: " << cache_path() << '\n';
        platform::write_stderr(os.str());
    }

    // Merge any signing-defaults flags into config.json.  Post-login
    // so a failed auth doesn't pollute the config.
    save_signing_defaults(cfg_endpoint, cfg_account, cfg_profile);

    return 0;
}

// ----- Config ----------------------------------------------------------

int config_main(int argc, char **argv)
{
    std::string endpoint, account, profile;

    for (int i = 2; i < argc; i++) {  // argv[1] == "config"
        if (!strcmp(argv[i], "--endpoint") && i + 1 < argc)
            endpoint = argv[++i];
        else if (!strcmp(argv[i], "--account") && i + 1 < argc)
            account = argv[++i];
        else if (!strcmp(argv[i], "--profile") && i + 1 < argc)
            profile = argv[++i];
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            std::ostringstream os;
            os
                << "usage: aas-sign config [--endpoint H] [--account N]"
                                                 " [--profile P]\n"
                << "\n"
                << "Write signing defaults to\n"
                << "    " << platform::config_dir() << "/config.json\n"
                << "without performing a login.  Any fields not passed are\n"
                << "preserved as they are in the existing file.  Equivalent\n"
                << "to passing the same flags to `aas-sign login`, minus the\n"
                << "auth step.\n"
                << "\n"
                << "  --endpoint H   Azure Trusted Signing endpoint hostname.\n"
                << "  --account N    Trusted Signing account name.\n"
                << "  --profile P    Certificate profile name.\n";
            platform::write_stdout(os.str());
            return 0;
        }
        else {
            platform::write_stderr(
                std::string("aas-sign config: unknown option: ") +
                argv[i] + "\n");
            return 1;
        }
    }

    if (endpoint.empty() && account.empty() && profile.empty()) {
        platform::write_stderr(
            "aas-sign config: nothing to do; pass at least one of"
            " --endpoint, --account, --profile\n");
        return 1;
    }

    save_signing_defaults(endpoint, account, profile);
    return 0;
}

// ----- Silent refresh --------------------------------------------------

std::string try_cached_refresh()
{
    json cache = read_cache();
    if (cache.is_null() || !cache.is_object()) return {};

    std::string refresh_token = cache.value("refresh_token", "");
    std::string client_id     = cache.value("client_id", "");
    std::string tenant_id     = cache.value("tenant_id", "");
    if (refresh_token.empty() || client_id.empty())
        return {};

    // If tenant wasn't captured (older cache), fall back to organizations.
    std::string tenant = tenant_id.empty() ? std::string(AAS_SIGN_DEFAULT_TENANT)
                                           : tenant_id;

    std::string form = form_encode({
        {"client_id",     client_id},
        {"grant_type",    "refresh_token"},
        {"refresh_token", refresh_token},
        {"scope",         SCOPE_SIGN},
    });

    auto resp = platform::https_post_url(
        token_url(tenant), "application/x-www-form-urlencoded", form);
    if (resp.status != 200) {
        // Parse the error body to distinguish recoverable from fatal.
        std::string err;
        try {
            err = json::parse(resp.body).value("error", "");
        } catch (...) {}
        if (err == "invalid_grant") {
            delete_cache();
            throw std::runtime_error(
                "cached refresh token was rejected (revoked or expired); "
                "run `aas-sign login` to sign in again");
        }
        throw std::runtime_error("token refresh failed (HTTP " +
                                 std::to_string(resp.status) + "): " +
                                 resp.body);
    }

    json body = json::parse(resp.body);
    std::string access_token  = body.value("access_token", "");
    std::string new_refresh   = body.value("refresh_token", "");
    if (access_token.empty())
        throw std::runtime_error("no access_token in refresh response");

    // AAD rotates refresh tokens -- persist the new one when present.
    if (!new_refresh.empty() && new_refresh != refresh_token) {
        cache["refresh_token"] = new_refresh;
        try { write_cache(cache); } catch (...) { /* non-fatal */ }
    }
    return access_token;
}

// ----- Logout ----------------------------------------------------------

int logout_main(int argc, char **argv)
{
    for (int i = 2; i < argc; i++) {  // argv[1] == "logout"
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            std::ostringstream os;
            os
                << "usage: aas-sign logout\n"
                << "\n"
                << "Delete the local refresh-token cache at\n"
                << "    " << cache_path() << "\n"
                << "\n"
                << "This only removes the local cache; the refresh token\n"
                << "remains valid on Microsoft's side until its natural\n"
                << "expiry (~90 days of inactivity) or until an admin\n"
                << "revokes it in the Entra portal.\n";
            platform::write_stdout(os.str());
            return 0;
        }
        platform::write_stderr(std::string("aas-sign logout: unknown option: ") +
                               argv[i] + "\n");
        return 1;
    }

    std::string p = cache_path();
    std::ifstream test(p);
    if (test) {
        test.close();
        delete_cache();
        platform::write_stderr("Logged out (removed " + p + ").\n");
    } else {
        platform::write_stderr("Not logged in (no cache at " + p + ").\n");
    }
    return 0;
}
