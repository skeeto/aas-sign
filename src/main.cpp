#include "app.hpp"
#include "azure.hpp"
#include "cms.hpp"
#include "pe.hpp"
#include "sha256.hpp"
#include "tsa.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

static const char DEFAULT_TSA_URL[] =
    "http://timestamp.acs.microsoft.com/timestamping/RFC3161";

static void usage(const char *argv0)
{
    std::cerr << "usage: " << argv0
              << " --endpoint HOST --account NAME --profile NAME"
              << " [--token TOKEN] [--dump-cms FILE]"
              << " [--timestamp-url URL | --no-timestamp]"
              << " [--max-parallel N] FILE [FILE ...]\n"
              << "       " << argv0 << " --version | --help\n";
}

struct Config {
    std::string endpoint;
    std::string account;
    std::string profile;
    std::string token;
    std::string timestamp_url;
    bool no_timestamp = false;
    std::string dump_cms;  // valid only when signing a single file
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

int aas_sign_main(int argc, char **argv)
{
    Config cfg;
    cfg.timestamp_url = DEFAULT_TSA_URL;
    std::vector<std::string> files;
    int max_parallel = 8;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--endpoint") && i + 1 < argc)
            cfg.endpoint = argv[++i];
        else if (!strcmp(argv[i], "--account") && i + 1 < argc)
            cfg.account = argv[++i];
        else if (!strcmp(argv[i], "--profile") && i + 1 < argc)
            cfg.profile = argv[++i];
        else if (!strcmp(argv[i], "--token") && i + 1 < argc)
            cfg.token = argv[++i];
        else if (!strcmp(argv[i], "--dump-cms") && i + 1 < argc)
            cfg.dump_cms = argv[++i];
        else if (!strcmp(argv[i], "--timestamp-url") && i + 1 < argc)
            cfg.timestamp_url = argv[++i];
        else if (!strcmp(argv[i], "--no-timestamp"))
            cfg.no_timestamp = true;
        else if (!strcmp(argv[i], "--max-parallel") && i + 1 < argc)
            max_parallel = std::max(1, atoi(argv[++i]));
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return 0;
        } else if (!strcmp(argv[i], "--version")) {
            std::cout << "aas-sign " << AAS_SIGN_VERSION << '\n';
            return 0;
        } else if (argv[i][0] != '-')
            files.push_back(argv[i]);
        else {
            std::cerr << "unknown option: " << argv[i] << '\n';
            usage(argv[0]);
            return 1;
        }
    }

    if (cfg.token.empty()) {
        const char *env = getenv("AZURE_ACCESS_TOKEN");
        if (env) cfg.token = env;
    }

    if (cfg.endpoint.empty() || cfg.account.empty() || cfg.profile.empty() ||
        cfg.token.empty() || files.empty()) {
        usage(argv[0]);
        return 1;
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
