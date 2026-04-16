#ifndef DER_H
#define DER_H

#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <vector>

using Bytes = std::vector<uint8_t>;

// Wrap content bytes with a DER tag-length header.
Bytes der_wrap(uint8_t tag, const uint8_t *data, size_t len);
Bytes der_wrap(uint8_t tag, const Bytes &content);
Bytes der_wrap(uint8_t tag, std::initializer_list<const Bytes *> parts);

// Concatenate multiple DER-encoded pieces.
Bytes der_cat(std::initializer_list<const Bytes *> parts);

// Primitive types.
Bytes der_integer(const uint8_t *data, size_t len);
Bytes der_integer(long value);
Bytes der_oid(const char *dotted);
Bytes der_octet_string(const uint8_t *data, size_t len);
Bytes der_octet_string(const Bytes &data);
Bytes der_bit_string(const uint8_t *data, size_t len);
Bytes der_null();

// Constructed types (convenience for tag + concatenated contents).
Bytes der_sequence(std::initializer_list<const Bytes *> parts);
Bytes der_set(std::initializer_list<const Bytes *> parts);

// Context tagging.
// EXPLICIT [tag_number] wraps the content with a constructed context tag.
Bytes der_explicit(unsigned tag_number, const Bytes &content);
// IMPLICIT [tag_number] rewrites the outermost tag of content.
Bytes der_implicit(unsigned tag_number, bool constructed, const Bytes &content);

// Splice raw pre-encoded DER bytes (no tag-length wrapping).
inline Bytes der_raw(const uint8_t *data, size_t len) {
    return Bytes(data, data + len);
}

// DER tag constants.
constexpr uint8_t DER_SEQUENCE = 0x30;
constexpr uint8_t DER_SET      = 0x31;

#endif
