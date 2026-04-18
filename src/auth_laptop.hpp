#pragma once

#include <string>

// Default Entra application (client) ID.  We reuse the public-client
// ID for "Microsoft Azure CLI" (04b07795-...), because Azure Trusted
// Signing publishes no OAuth scopes on its service principal, which
// means third-party apps hit AADSTS650057 at token exchange.
// Microsoft first-party apps are exempt from that check.
//
// This is the standard escape hatch for third-party tools that want
// to acquire Azure resource tokens from interactive user sessions --
// the Go Azure SDK uses the same client_id
// (sdk/environments/constants.go), and plenty of other Azure-adjacent
// tooling does the same.  The client_id is labelled a *public* client:
// it has no secret, its value is published in Microsoft's source, and
// reusing it doesn't delegate any authority beyond what the user
// signed in with.
//
// For the CI OIDC flow we still use the repo's own app registration
// (f71e0d72-...) -- see the workflow's --oidc-client-id input, which
// overrides this default.
constexpr const char AAS_SIGN_DEFAULT_CLIENT_ID[] =
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46";

// Default tenant for `aas-sign login`.  The repo owner's Entra tenant,
// where the Trusted Signing account lives.  Signing in at a specific
// tenant GUID unambiguously routes MSA-guest accounts (which is the
// repo owner's setup); `organizations` alone doesn't, because Entra
// then picks the client_id's home tenant (Microsoft Services) and
// rejects outside accounts.  Users signing against a different tenant
// pass --tenant <theirs>.
constexpr const char AAS_SIGN_DEFAULT_TENANT[] =
    "fd996ec3-65fc-49a8-a18b-2f8fd65d7b2d";

// Run the `aas-sign login` subcommand: OAuth 2.0 Authorization Code
// + PKCE against Microsoft Entra, writes a refresh-token cache.
int login_main(int argc, char **argv);

// Attempt to read the cached refresh token and exchange it for a
// fresh access token for the codesigning.azure.net scope.  Returns
// the empty string if no cache exists; throws std::runtime_error on
// any other failure.  On `invalid_grant` (cache revoked/expired),
// deletes the cache file before throwing.
std::string try_cached_refresh();
