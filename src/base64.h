#ifndef BASE64_H
#define BASE64_H

#include <cstdint>
#include <string>
#include <vector>

std::string base64_encode(const uint8_t *data, size_t len);
std::vector<uint8_t> base64_decode(const std::string &s);
std::vector<uint8_t> base64_mime_decode(const std::string &s);

#endif
