#pragma once

#include <string>

// Compact encoding of a Trusted Signing target as a single colon-
// delimited tuple: `region:account:profile`.  Example:
//
//     eus:mycompany:me
//
// expands to endpoint=eus.codesigning.azure.net, account=mycompany,
// profile=me.  If the region field contains a `.` it's treated as a
// full hostname verbatim:
//
//     custom.example.com:mycompany:me
//
// Azure resource names never contain `:`, so the split is
// unambiguous.  Used by `aas-sign login TUPLE`, `aas-sign config
// TUPLE`, and `aas-sign sign --as TUPLE`.

struct SignerTuple {
    std::string endpoint;   // post-expansion hostname
    std::string account;
    std::string profile;
};

// Parse `region:account:profile`.  Exactly three non-empty fields
// separated by two colons; anything else is an error.  Applies the
// region shorthand expansion (no-dot → append
// `.codesigning.azure.net`).  Throws std::runtime_error with a
// user-friendly message on any parse failure.
SignerTuple parse_signer_tuple(const std::string &s);
