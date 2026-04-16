#include "azure.h"
#include "cms.h"
#include "pe.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

static void usage(const char *argv0)
{
    std::cerr << "usage: " << argv0
              << " --endpoint HOST --account NAME --profile NAME"
              << " [--token TOKEN] [--dump-cms FILE] FILE\n";
}

int main(int argc, char **argv)
{
    std::string endpoint, account, profile, token, file, dump_cms;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--endpoint") && i + 1 < argc)
            endpoint = argv[++i];
        else if (!strcmp(argv[i], "--account") && i + 1 < argc)
            account = argv[++i];
        else if (!strcmp(argv[i], "--profile") && i + 1 < argc)
            profile = argv[++i];
        else if (!strcmp(argv[i], "--token") && i + 1 < argc)
            token = argv[++i];
        else if (!strcmp(argv[i], "--dump-cms") && i + 1 < argc)
            dump_cms = argv[++i];
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-')
            file = argv[i];
        else {
            std::cerr << "unknown option: " << argv[i] << '\n';
            usage(argv[0]);
            return 1;
        }
    }

    if (token.empty()) {
        const char *env = getenv("AZURE_ACCESS_TOKEN");
        if (env) token = env;
    }

    if (endpoint.empty() || account.empty() || profile.empty() ||
        token.empty() || file.empty()) {
        usage(argv[0]);
        return 1;
    }

    try {
        // Open and validate PE.
        PeFile pe(file);
        std::cerr << "PE format: " << (pe.is_pe32plus ? "PE32+" : "PE32")
                  << '\n';

        // Step 1: Compute Authenticode hash.
        auto pe_hash = pe.authenticode_hash();
        std::cerr << "Authenticode SHA-256: ";
        for (auto b : pe_hash)
            fprintf(stderr, "%02x", b);
        std::cerr << '\n';

        // Step 2: Compute SHA-256 of authenticated attributes.
        auto attrs_hash = cms_auth_attrs_hash(pe_hash);

        // Step 3: Sign via Azure.
        std::cerr << "Signing...\n";
        auto sign_result = azure_sign(endpoint, account, profile,
                                      token, attrs_hash.data(),
                                      attrs_hash.size());

        // Step 4: Build CMS and inject into PE.
        auto cms_der = cms_build_authenticode(pe_hash,
                                              sign_result.signature,
                                              sign_result.cert_chain_der);

        if (!dump_cms.empty()) {
            std::ofstream out(dump_cms, std::ios::binary);
            out.write(reinterpret_cast<const char *>(cms_der.data()),
                      cms_der.size());
            std::cerr << "CMS blob written to " << dump_cms
                      << " (" << cms_der.size() << " bytes)\n";
        }

        std::cerr << "Injecting signature (" << cms_der.size()
                  << " bytes)...\n";
        pe.inject_signature(cms_der);

        std::cerr << "Signed " << file << " successfully.\n";
        return 0;

    } catch (const std::exception &e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
}
