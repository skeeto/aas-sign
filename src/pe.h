#ifndef PE_H
#define PE_H

#include "sha256.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

struct PeFile {
    platform::File file;
    uint64_t pe_offset;        // offset to PE\0\0 signature
    bool is_pe32plus;          // PE32+ (64-bit) vs PE32 (32-bit)
    uint64_t data_dir_offset;  // offset to data directory table

    PeFile(const std::string &path);
    PeFile(const PeFile &) = delete;
    PeFile &operator=(const PeFile &) = delete;

    // Compute the Authenticode SHA-256 digest.
    std::array<uint8_t, 32> authenticode_hash();

    // Inject a signature (DER-encoded CMS ContentInfo wrapped in
    // WIN_CERTIFICATE) into the PE. Updates data directory and checksum.
    void inject_signature(const std::vector<uint8_t> &cms_der);

private:
    uint64_t checksum_offset();
    uint64_t cert_table_entry_offset();
    void read_at(uint64_t offset, void *buf, size_t len);
    void write_at(uint64_t offset, const void *buf, size_t len);
    uint32_t read_le32(uint64_t offset);
    uint16_t read_le16(uint64_t offset);
    void write_le32(uint64_t offset, uint32_t val);
    uint64_t file_size();
    void recompute_checksum();
};

#endif
