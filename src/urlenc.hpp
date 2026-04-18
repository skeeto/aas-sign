#pragma once

#include <string>

// Percent-encode per RFC 3986 "unreserved" set ([A-Za-z0-9._~-]); all
// other bytes become %XX.  Safe for form bodies, query strings, and
// path segments.  Shared between oidc.cpp (CI token exchange) and
// auth_laptop.cpp (interactive login flow).
std::string url_encode(const std::string &s);
