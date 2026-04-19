#include "signer.hpp"

#include <stdexcept>

static const char TRUSTED_SIGNING_DOMAIN[] = ".codesigning.azure.net";

SignerTuple parse_signer_tuple(const std::string &s)
{
    auto fail = [&](const char *why) {
        throw std::runtime_error(
            std::string("invalid signer tuple \"") + s + "\": " + why +
            " (expected REGION:ACCOUNT:PROFILE)");
    };

    // Exactly two `:` separators.
    auto a = s.find(':');
    if (a == std::string::npos)
        fail("missing ':' separator");
    auto b = s.find(':', a + 1);
    if (b == std::string::npos)
        fail("missing second ':' separator");
    if (s.find(':', b + 1) != std::string::npos)
        fail("too many ':' separators");

    SignerTuple out;
    std::string region = s.substr(0, a);
    out.account        = s.substr(a + 1, b - a - 1);
    out.profile        = s.substr(b + 1);

    if (region.empty())      fail("empty region");
    if (out.account.empty()) fail("empty account");
    if (out.profile.empty()) fail("empty profile");

    // Region shorthand: a bare label (no '.') is an
    // aas-sign convention for "the codesigning.azure.net host in
    // that region."  A fully-qualified hostname goes through
    // verbatim, so users can point at non-production endpoints if
    // Microsoft ever offers them.
    if (region.find('.') == std::string::npos)
        out.endpoint = region + TRUSTED_SIGNING_DOMAIN;
    else
        out.endpoint = std::move(region);

    return out;
}
