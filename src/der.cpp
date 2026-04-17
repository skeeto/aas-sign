#include "der.hpp"
#include <algorithm>
#include <stdexcept>

static void write_length(Bytes &out, size_t len)
{
    if (len < 0x80) {
        out.push_back(uint8_t(len));
    } else if (len < 0x100) {
        out.push_back(0x81);
        out.push_back(uint8_t(len));
    } else if (len < 0x10000) {
        out.push_back(0x82);
        out.push_back(uint8_t(len >> 8));
        out.push_back(uint8_t(len));
    } else if (len < 0x1000000) {
        out.push_back(0x83);
        out.push_back(uint8_t(len >> 16));
        out.push_back(uint8_t(len >> 8));
        out.push_back(uint8_t(len));
    } else {
        out.push_back(0x84);
        out.push_back(uint8_t(len >> 24));
        out.push_back(uint8_t(len >> 16));
        out.push_back(uint8_t(len >> 8));
        out.push_back(uint8_t(len));
    }
}

Bytes der_wrap(uint8_t tag, const uint8_t *data, size_t len)
{
    Bytes out;
    out.push_back(tag);
    write_length(out, len);
    out.insert(out.end(), data, data + len);
    return out;
}

Bytes der_wrap(uint8_t tag, const Bytes &content)
{
    return der_wrap(tag, content.data(), content.size());
}

Bytes der_wrap(uint8_t tag, std::initializer_list<const Bytes *> parts)
{
    return der_wrap(tag, der_cat(parts));
}

Bytes der_cat(std::initializer_list<const Bytes *> parts)
{
    size_t total = 0;
    for (auto *p : parts) total += p->size();
    Bytes out;
    out.reserve(total);
    for (auto *p : parts)
        out.insert(out.end(), p->begin(), p->end());
    return out;
}

Bytes der_integer(const uint8_t *data, size_t len)
{
    // Skip leading zero bytes, but keep at least one.
    while (len > 1 && data[0] == 0 && !(data[1] & 0x80)) {
        data++;
        len--;
    }
    // If high bit is set, prepend a zero byte.
    if (len > 0 && (data[0] & 0x80)) {
        Bytes content;
        content.push_back(0);
        content.insert(content.end(), data, data + len);
        return der_wrap(0x02, content);
    }
    return der_wrap(0x02, data, len);
}

Bytes der_integer(int64_t value)
{
    if (value < 0)
        throw std::runtime_error("negative integers not supported");
    // Encode as minimal big-endian bytes.
    uint8_t buf[8];
    int n = 0;
    if (value == 0) {
        buf[0] = 0;
        n = 1;
    } else {
        uint64_t v = uint64_t(value);
        // Find number of bytes needed.
        int nbytes = 0;
        for (uint64_t tmp = v; tmp > 0; tmp >>= 8) nbytes++;
        n = nbytes;
        for (int i = nbytes - 1; i >= 0; i--) {
            buf[i] = uint8_t(v & 0xff);
            v >>= 8;
        }
    }
    return der_integer(buf, size_t(n));
}

Bytes der_oid(const char *dotted)
{
    Bytes content;
    // Parse dotted form.
    std::vector<unsigned long> components;
    const char *p = dotted;
    while (*p) {
        char *end;
        components.push_back(strtoul(p, &end, 10));
        p = end;
        if (*p == '.') p++;
    }
    if (components.size() < 2)
        throw std::runtime_error("OID must have at least 2 components");

    // First two components: 40*c1 + c2.
    content.push_back(uint8_t(40 * components[0] + components[1]));

    // Remaining components: base-128 with continuation bits.
    for (size_t i = 2; i < components.size(); i++) {
        unsigned long v = components[i];
        uint8_t buf[10];
        int n = 0;
        do {
            buf[n++] = uint8_t(v & 0x7f);
            v >>= 7;
        } while (v > 0);
        for (int j = n - 1; j > 0; j--)
            content.push_back(buf[j] | 0x80);
        content.push_back(buf[0]);
    }

    return der_wrap(0x06, content);
}

Bytes der_octet_string(const uint8_t *data, size_t len)
{
    return der_wrap(0x04, data, len);
}

Bytes der_octet_string(const Bytes &data)
{
    return der_wrap(0x04, data);
}

Bytes der_bit_string(const uint8_t *data, size_t len)
{
    Bytes content;
    content.push_back(0);  // unused bits = 0
    content.insert(content.end(), data, data + len);
    return der_wrap(0x03, content);
}

Bytes der_boolean(bool value)
{
    return {0x01, 0x01, uint8_t(value ? 0xff : 0x00)};
}

Bytes der_null()
{
    return {0x05, 0x00};
}

Bytes der_sequence(std::initializer_list<const Bytes *> parts)
{
    return der_wrap(DER_SEQUENCE, parts);
}

Bytes der_set(std::initializer_list<const Bytes *> parts)
{
    // DER requires SET OF elements to be sorted lexicographically by their
    // encoded bytes.  Sorting is harmless for single-element sets or for SET
    // types where the schema order happens to match canonical order.
    std::vector<const Bytes *> sorted(parts.begin(), parts.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const Bytes *a, const Bytes *b) {
                  return std::lexicographical_compare(
                      a->begin(), a->end(), b->begin(), b->end());
              });
    Bytes content;
    for (auto *p : sorted)
        content.insert(content.end(), p->begin(), p->end());
    return der_wrap(DER_SET, content);
}

Bytes der_explicit(unsigned tag_number, const Bytes &content)
{
    uint8_t tag = 0xa0 | uint8_t(tag_number & 0x1f);
    return der_wrap(tag, content);
}

Bytes der_implicit(unsigned tag_number, bool constructed, const Bytes &content)
{
    if (content.empty())
        throw std::runtime_error("cannot implicit-tag empty content");
    Bytes out = content;
    uint8_t tag = 0x80 | uint8_t(tag_number & 0x1f);
    if (constructed) tag |= 0x20;
    out[0] = tag;
    return out;
}
