#pragma once

#include <string>

// Runner-injected env vars for GitHub Actions OIDC.  Both fields are
// empty if the process isn't running inside a GitHub Actions runner
// that has `permissions: id-token: write` granted to the workflow.
struct OidcRuntime {
    std::string request_url;    // ACTIONS_ID_TOKEN_REQUEST_URL
    std::string request_token;  // ACTIONS_ID_TOKEN_REQUEST_TOKEN
};

// Read the OIDC runtime env vars.  Returns empty fields if absent.
OidcRuntime oidc_runtime();

// Perform the two-step GitHub-OIDC -> Azure-token exchange using
// Microsoft's federated-credential flow.  Returns the Azure access
// token (the same bearer as `az account get-access-token --resource
// https://codesigning.azure.net`).
//
// Throws std::runtime_error on any HTTP error, JSON parse failure, or
// if the runtime's request_url/request_token are empty.
std::string oidc_fetch_azure_token(const OidcRuntime &runtime,
                                   const std::string &client_id,
                                   const std::string &tenant_id);
