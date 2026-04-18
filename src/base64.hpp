#pragma once

#include <cstdint>
#include <string>
#include <vector>

std::string base64_encode(const uint8_t *data, size_t len);
std::vector<uint8_t> base64_decode(const std::string &s);
std::vector<uint8_t> base64_mime_decode(const std::string &s);

// URL-safe base64 (alphabet -_ instead of +/), no padding.  Used for
// OAuth 2.0 PKCE code_verifier/code_challenge and for parsing JWT
// segments.
std::string base64url_encode(const uint8_t *data, size_t len);
std::vector<uint8_t> base64url_decode(const std::string &s);

