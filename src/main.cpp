#include "app.hpp"
#include "auth_laptop.hpp"
#include "azure.hpp"
#include "cms.hpp"
#include "oidc.hpp"
#include "pe.hpp"
#include "sha256.hpp"
#include "tsa.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

static const char DEFAULT_TSA_URL[] =
    "http://timestamp.acs.microsoft.com/timestamping/RFC3161";

static void usage_short(std::ostream &os, const char *argv0)
{
    os << "usage: " << argv0 << " sign [options] FILE [FILE ...]\n"
       << "       " << argv0 << " login [--tenant T] [--client-id C]\n"
       << "       " << argv0 << " logout\n"
       << "Try `" << argv0 << " --help' for more information.\n";
}

static void usage_full(const char *argv0)
{
    std::cout
        << "usage: " << argv0 << " sign [options] FILE [FILE ...]\n"
        << "       " << argv0 << " login [--tenant T] [--client-id C]\n"
        << "       " << argv0 << " logout\n"
        << "       " << argv0 << " --version | --help\n"
        << "\n"
        << "Sign PE images (EXE, DLL) via Azure Artifact Signing "
           "(Trusted Signing).\n"
        << "\n"
        << "Subcommands:\n"
        << "  sign FILE ...        Sign one or more PE images.\n"
        << "  login                Interactive browser login; caches a refresh\n"
        << "                       token under ${XDG_CONFIG_HOME:-~/.config}/\n"
        << "                       aas-sign (or %APPDATA%\\aas-sign on Windows).\n"
        << "                       Subsequent `sign` runs then use the cache.\n"
        << "  logout               Delete the cached refresh token.\n"
        << "\n"
        << "sign options:\n"
        << "  --endpoint HOST      Azure Trusted Signing endpoint hostname,\n"
        << "                       e.g. eus.codesigning.azure.net.  Required.\n"
        << "  --account NAME       Trusted Signing account name.  Required.\n"
        << "  --profile NAME       Certificate profile name.  Required.\n"
        << "  --token TOKEN        Azure bearer token.  Falls back to the\n"
        << "                       AZURE_ACCESS_TOKEN environment variable.\n"
        << "  --oidc-client-id ID  Azure app client ID.  Combined with\n"
        << "                       --oidc-tenant-id, mints a token from GitHub\n"
        << "                       Actions OIDC federation (CI only; requires\n"
        << "                       permissions: id-token: write).  Falls back\n"
        << "                       to the AZURE_CLIENT_ID environment variable.\n"
        << "  --oidc-tenant-id ID  Azure tenant ID for --oidc-client-id.\n"
        << "                       Falls back to AZURE_TENANT_ID.\n"
        << "  --timestamp-url URL  RFC 3161 timestamp authority.  Default is\n"
        << "                       Microsoft's public TSA.  Use --no-timestamp\n"
        << "                       to skip.\n"
        << "  --no-timestamp       Skip timestamping.  Not recommended -- Azure\n"
        << "                       Trusted Signing certs are short-lived (days).\n"
        << "  --max-parallel N     Maximum concurrent sign operations when\n"
        << "                       signing multiple files.  Default: 8.\n"
        << "  --dump-cms FILE      Write raw CMS DER blob to FILE for debugging\n"
        << "                       (openssl asn1parse -inform DER).  Single-file\n"
        << "                       mode only.\n"
        << "\n"
        << "If no token source is provided, aas-sign sign will attempt to use\n"
        << "a refresh token cached by a prior `aas-sign login`.\n"
        << "\n"
        << "--endpoint, --account, and --profile can also be pre-filled by\n"
        << "putting them in ${XDG_CONFIG_HOME:-~/.config}/aas-sign/config.json\n"
        << "(or %APPDATA%\\aas-sign\\config.json on Windows):\n"
        << "\n"
        << "    { \"endpoint\": \"eus.codesigning.azure.net\",\n"
        << "      \"account\": \"myaccount\",\n"
        << "      \"profile\": \"myprofile\" }\n"
        << "\n"
        << "login options:\n"
        << "  --tenant TENANT      Azure tenant (default: organizations).\n"
        << "  --client-id ID       Override the default aas-sign app ID.\n"
        << "\n"
        << "  --version            Print version and exit.\n"
        << "  --help, -h           Print this help and exit.\n";
}

struct Config {
    std::string endpoint;
    std::string account;
    std::string profile;
    std::string token;
    std::string timestamp_url;
    bool no_timestamp = false;
    std::string dump_cms;  // valid only when signing a single file
    // OIDC (CI-only) mode: when --token/$AZURE_ACCESS_TOKEN aren't set
    // but both of these are, perform the GitHub-Actions OIDC flow to
    // mint an Azure bearer.
    std::string oidc_client_id;
    std::string oidc_tenant_id;
};

struct SignResult {
    std::string file;
    bool ok = false;
    std::string error;  // empty iff ok
};

// Logger that either writes straight to std::cerr (single-file mode) or
// buffers lines with a "[file] " prefix and emits the whole block at once
// (multi-file mode).  Flushing under a shared mutex keeps concurrent file
// narratives from interleaving.
class FileLogger {
public:
    FileLogger(std::string file, bool multi)
        : multi_(multi), prefix_("[" + std::move(file) + "] ") {}

    std::ostream &line()
    {
        if (multi_)
            return buf_ << prefix_;
        return std::cerr;
    }

    void flush(std::mutex &mu)
    {
        if (!multi_) return;
        std::lock_guard<std::mutex> g(mu);
        std::cerr << buf_.str();
        std::cerr.flush();
        buf_.str({});
    }

private:
    bool multi_;
    std::string prefix_;
    std::ostringstream buf_;
};

static SignResult sign_one_file(const std::string &file, const Config &cfg,
                                FileLogger &log)
{
    SignResult r;
    r.file = file;
    try {
        // Open and validate PE.
        PeFile pe(file);
        log.line() << "PE format: "
                   << (pe.is_pe32plus ? "PE32+" : "PE32") << '\n';

        // Compute Authenticode hash.
        auto pe_hash = pe.authenticode_hash();
        {
            auto &ls = log.line();
            ls << "Authenticode SHA-256: ";
            char buf[3];
            for (auto b : pe_hash) {
                std::snprintf(buf, sizeof(buf), "%02x", b);
                ls << buf;
            }
            ls << '\n';
        }

        // Compute SHA-256 of authenticated attributes.
        auto attrs_hash = cms_auth_attrs_hash(pe_hash);

        // Sign via Azure.
        log.line() << "Signing...\n";
        auto sign_result = azure_sign(cfg.endpoint, cfg.account, cfg.profile,
                                      cfg.token, attrs_hash.data(),
                                      attrs_hash.size());

        // RFC 3161 timestamp (optional).
        std::vector<uint8_t> timestamp_token;
        if (!cfg.no_timestamp) {
            log.line() << "Requesting timestamp from " << cfg.timestamp_url
                       << " ...\n";
            timestamp_token = tsa_timestamp(cfg.timestamp_url,
                                            sign_result.signature);
            log.line() << "Timestamp token received ("
                       << timestamp_token.size() << " bytes)\n";
        }

        // Build CMS and inject into PE.
        auto cms_der = cms_build_authenticode(pe_hash,
                                              sign_result.signature,
                                              sign_result.cert_chain_der,
                                              timestamp_token);

        if (!cfg.dump_cms.empty()) {
            platform::write_whole_file(cfg.dump_cms, cms_der.data(),
                                       cms_der.size());
            log.line() << "CMS blob written to " << cfg.dump_cms
                       << " (" << cms_der.size() << " bytes)\n";
        }

        log.line() << "Injecting signature (" << cms_der.size()
                   << " bytes)...\n";
        pe.inject_signature(cms_der);

        log.line() << "Signed " << file << " successfully.\n";
        r.ok = true;
    } catch (const std::exception &e) {
        log.line() << "error: " << e.what() << '\n';
        r.error = e.what();
    }
    return r;
}

static int sign_main(int argc, char **argv)
{
    Config cfg;
    cfg.timestamp_url = DEFAULT_TSA_URL;
    std::vector<std::string> files;
    int max_parallel = 8;

    // argv[1] is "sign" (guaranteed by aas_sign_main dispatch).
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--endpoint") && i + 1 < argc)
            cfg.endpoint = argv[++i];
        else if (!strcmp(argv[i], "--account") && i + 1 < argc)
            cfg.account = argv[++i];
        else if (!strcmp(argv[i], "--profile") && i + 1 < argc)
            cfg.profile = argv[++i];
        else if (!strcmp(argv[i], "--token") && i + 1 < argc)
            cfg.token = argv[++i];
        else if (!strcmp(argv[i], "--oidc-client-id") && i + 1 < argc)
            cfg.oidc_client_id = argv[++i];
        else if (!strcmp(argv[i], "--oidc-tenant-id") && i + 1 < argc)
            cfg.oidc_tenant_id = argv[++i];
        else if (!strcmp(argv[i], "--dump-cms") && i + 1 < argc)
            cfg.dump_cms = argv[++i];
        else if (!strcmp(argv[i], "--timestamp-url") && i + 1 < argc)
            cfg.timestamp_url = argv[++i];
        else if (!strcmp(argv[i], "--no-timestamp"))
            cfg.no_timestamp = true;
        else if (!strcmp(argv[i], "--max-parallel") && i + 1 < argc)
            max_parallel = std::max(1, atoi(argv[++i]));
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage_full(argv[0]);
            return 0;
        } else if (!strcmp(argv[i], "--version")) {
            std::cout << "aas-sign " << AAS_SIGN_VERSION << '\n';
            return 0;
        } else if (argv[i][0] != '-')
            files.push_back(argv[i]);
        else {
            std::cerr << "unknown option: " << argv[i] << '\n';
            usage_short(std::cerr, argv[0]);
            return 1;
        }
    }

    // Fill missing --endpoint/--account/--profile from a user-local
    // config file if present, so laptop users don't retype them every
    // invocation.  CLI flags still win.  Missing file or missing fields
    // are fine -- the required-arg check below surfaces anything left
    // unset.
    try {
        std::ifstream f(platform::config_dir() + "/config.json");
        if (f) {
            nlohmann::json j;
            f >> j;
            if (cfg.endpoint.empty()) cfg.endpoint = j.value("endpoint", "");
            if (cfg.account.empty())  cfg.account  = j.value("account", "");
            if (cfg.profile.empty())  cfg.profile  = j.value("profile", "");
        }
    } catch (const std::exception &e) {
        std::cerr << "warning: ignoring unreadable config.json: "
                  << e.what() << '\n';
    }

    // Token resolution, in order of precedence:
    //   1. --token
    //   2. $AZURE_ACCESS_TOKEN
    //   3. OIDC (if --oidc-client-id + --oidc-tenant-id, or their env
    //      fallbacks AZURE_CLIENT_ID/AZURE_TENANT_ID, are set AND the
    //      runner has injected the id-token endpoint)
    //   4. Cached refresh token from a prior `aas-sign login`.
    if (cfg.token.empty()) {
        if (const char *env = getenv("AZURE_ACCESS_TOKEN"))
            cfg.token = env;
    }
    if (cfg.oidc_client_id.empty())
        if (const char *env = getenv("AZURE_CLIENT_ID"))
            cfg.oidc_client_id = env;
    if (cfg.oidc_tenant_id.empty())
        if (const char *env = getenv("AZURE_TENANT_ID"))
            cfg.oidc_tenant_id = env;

    if (cfg.token.empty() &&
        !cfg.oidc_client_id.empty() && !cfg.oidc_tenant_id.empty()) {
        std::cerr << "Fetching Azure token via GitHub OIDC federation...\n";
        try {
            cfg.token = oidc_fetch_azure_token(oidc_runtime(),
                                               cfg.oidc_client_id,
                                               cfg.oidc_tenant_id);
        } catch (const std::exception &e) {
            std::cerr << "error: " << e.what() << '\n';
            return 1;
        }
    }

    if (cfg.token.empty()) {
        try {
            cfg.token = try_cached_refresh();
            if (!cfg.token.empty())
                std::cerr << "Using cached login.\n";
        } catch (const std::exception &e) {
            std::cerr << "error: " << e.what() << '\n';
            return 1;
        }
    }

    {
        bool ok = true;
        auto require = [&](bool present, const char *what) {
            if (!present) {
                std::cerr << argv[0] << ": missing " << what << '\n';
                ok = false;
            }
        };
        require(!cfg.endpoint.empty(), "--endpoint");
        require(!cfg.account.empty(),  "--account");
        require(!cfg.profile.empty(),  "--profile");
        require(!cfg.token.empty(),
                "authentication -- pass --token, set $AZURE_ACCESS_TOKEN, "
                "use --oidc-* (in CI), or run `aas-sign login` first");
        require(!files.empty(),        "input file");
        if (!ok) {
            usage_short(std::cerr, argv[0]);
            return 1;
        }
    }

    if (files.size() > 1 && !cfg.dump_cms.empty()) {
        std::cerr
            << "error: --dump-cms only supported when signing a single file\n";
        return 1;
    }

    // Single-file fast path: straight to std::cerr, no threading, preserves
    // today's exact output and stack-trace behavior.
    if (files.size() == 1) {
        FileLogger fl(files[0], /*multi=*/false);
        auto r = sign_one_file(files[0], cfg, fl);
        return r.ok ? 0 : 1;
    }

    // Multi-file: bounded worker pool.  Each worker pulls the next index
    // from an atomic counter until there are no more files.
    const size_t n_files = files.size();
    const size_t n_workers = std::min<size_t>(size_t(max_parallel), n_files);
    std::atomic<size_t> next{0};
    std::vector<SignResult> results(n_files);
    std::mutex log_mu;

    {
        std::vector<std::jthread> workers;
        workers.reserve(n_workers);
        for (size_t t = 0; t < n_workers; t++) {
            workers.emplace_back([&] {
                size_t idx;
                while ((idx = next.fetch_add(1)) < n_files) {
                    FileLogger fl(files[idx], /*multi=*/true);
                    {
                        std::lock_guard<std::mutex> g(log_mu);
                        std::cerr << "[" << files[idx] << "] starting\n";
                    }
                    results[idx] = sign_one_file(files[idx], cfg, fl);
                    fl.flush(log_mu);
                }
            });
        }
    }  // jthreads join on scope exit

    // Summary.
    size_t ok_count = 0;
    std::vector<const SignResult *> failures;
    for (const auto &r : results) {
        if (r.ok) ok_count++;
        else failures.push_back(&r);
    }
    std::cerr << "Signed " << ok_count << "/" << n_files << " files";
    if (failures.empty()) {
        std::cerr << " successfully.\n";
        return 0;
    }
    std::cerr << ". Failures:\n";
    for (auto *f : failures)
        std::cerr << "  " << f->file << ": " << f->error << '\n';
    return 1;
}

// Top-level dispatch: the first non-flag arg is a subcommand
// (`sign` or `login`).  Bare --version/--help at argv[1] are
// accepted as top-level conveniences; everything else routes to
// a subcommand.
int aas_sign_main(int argc, char **argv)
{
    if (argc < 2) {
        usage_short(std::cerr, argv[0]);
        return 1;
    }
    if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
        usage_full(argv[0]);
        return 0;
    }
    if (!strcmp(argv[1], "--version")) {
        std::cout << "aas-sign " << AAS_SIGN_VERSION << '\n';
        return 0;
    }
    if (!strcmp(argv[1], "sign"))
        return sign_main(argc, argv);
    if (!strcmp(argv[1], "login"))
        return login_main(argc, argv);
    if (!strcmp(argv[1], "logout"))
        return logout_main(argc, argv);

    std::cerr << argv[0] << ": unknown subcommand: " << argv[1] << '\n';
    usage_short(std::cerr, argv[0]);
    return 1;
}
