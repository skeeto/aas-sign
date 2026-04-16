#include "base64.h"

static const char table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const uint8_t *data, size_t len)
{
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = uint32_t(data[i]) << 16;
        if (i + 1 < len) n |= uint32_t(data[i + 1]) << 8;
        if (i + 2 < len) n |= uint32_t(data[i + 2]);
        out.push_back(table[(n >> 18) & 0x3f]);
        out.push_back(table[(n >> 12) & 0x3f]);
        out.push_back(i + 1 < len ? table[(n >> 6) & 0x3f] : '=');
        out.push_back(i + 2 < len ? table[n & 0x3f] : '=');
    }
    return out;
}

static int decode_char(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

std::vector<uint8_t> base64_decode(const std::string &s)
{
    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);
    uint32_t accum = 0;
    int bits = 0;
    for (char c : s) {
        int v = decode_char(c);
        if (v < 0) continue;
        accum = (accum << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(uint8_t((accum >> bits) & 0xff));
        }
    }
    return out;
}

std::vector<uint8_t> base64_mime_decode(const std::string &s)
{
    return base64_decode(s);
}
