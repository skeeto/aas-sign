#include "pe.hpp"
#include "narrow.hpp"
#include "platform.hpp"
#include <algorithm>
#include <cstring>
#include <stdexcept>

PeFile::PeFile(const std::string &path) : file(path)
{
    // Validate MZ header.
    uint8_t mz[2];
    read_at(0, mz, 2);
    if (mz[0] != 'M' || mz[1] != 'Z')
        throw std::runtime_error("not a PE file: missing MZ signature");

    // PE header offset at 0x3C.
    pe_offset = read_le32(0x3c);

    // Validate PE\0\0 signature.
    uint8_t sig[4];
    read_at(pe_offset, sig, 4);
    if (memcmp(sig, "PE\0\0", 4) != 0)
        throw std::runtime_error("not a PE file: missing PE signature");

    // PE32 vs PE32+ from optional header magic.
    uint16_t magic = read_le16(pe_offset + 24);
    if (magic == 0x20b)
        is_pe32plus = true;
    else if (magic == 0x10b)
        is_pe32plus = false;
    else
        throw std::runtime_error("unknown PE optional header magic");

    // Data directory table offset.
    data_dir_offset = pe_offset + (is_pe32plus ? 136 : 120);
}

uint64_t PeFile::checksum_offset()
{
    return pe_offset + 88;
}

uint64_t PeFile::cert_table_entry_offset()
{
    // Certificate table is data directory index 4, each entry is 8 bytes.
    return data_dir_offset + 4 * 8;
}

std::array<uint8_t, 32> PeFile::authenticode_hash()
{
    platform::Sha256 hash;
    uint64_t fsize = file_size();
    uint64_t cksum = checksum_offset();
    uint64_t cert_entry = cert_table_entry_offset();

    // Read the certificate table directory entry.
    uint32_t cert_addr = read_le32(cert_entry);
    uint32_t cert_size = read_le32(cert_entry + 4);
    bool has_cert = cert_addr != 0 && cert_size != 0;

    // Helper: hash a range of the file.
    auto hash_range = [&](uint64_t start, uint64_t end) {
        uint8_t buf[8192];
        uint64_t pos = start;
        while (pos < end) {
            size_t n = size_t(std::min(uint64_t(sizeof(buf)), end - pos));
            read_at(pos, buf, n);
            hash.update(buf, n);
            pos += n;
        }
    };

    // Region 1: start of file to checksum field.
    hash_range(0, cksum);
    // Skip 4-byte checksum.
    // Region 2: after checksum to certificate table entry.
    hash_range(cksum + 4, cert_entry);
    // Skip 8-byte certificate table entry.
    uint64_t after_entry = cert_entry + 8;

    if (has_cert) {
        // Region 3: after cert entry to start of certificate table data.
        hash_range(after_entry, cert_addr);
        // Skip certificate table data.
        // Region 4: after certificate table to end of file.
        hash_range(uint64_t(cert_addr) + cert_size, fsize);
    } else {
        // Region 3: after cert entry to end of file.
        hash_range(after_entry, fsize);
        // Pad to 8-byte boundary.
        size_t pad = size_t((8 - fsize % 8) % 8);
        if (pad > 0) {
            uint8_t zeros[8] = {};
            hash.update(zeros, pad);
        }
    }

    return hash.finish();
}

void PeFile::inject_signature(const std::vector<uint8_t> &cms_der)
{
    // Build WIN_CERTIFICATE structure.
    // Pad CMS blob to 8-byte alignment.
    size_t padded = cms_der.size();
    size_t pad = (8 - padded % 8) % 8;
    padded += pad;

    uint32_t dwLength = uint32_t(8 + padded);
    uint16_t wRevision = 0x0200;
    uint16_t wCertificateType = 0x0002;

    std::vector<uint8_t> win_cert(8 + padded, 0);
    memcpy(win_cert.data(), &dwLength, 4);
    memcpy(win_cert.data() + 4, &wRevision, 2);
    memcpy(win_cert.data() + 6, &wCertificateType, 2);
    memcpy(win_cert.data() + 8, cms_der.data(), cms_der.size());

    // Determine where to write.
    uint64_t fsize = file_size();
    uint32_t cert_addr = read_le32(cert_table_entry_offset());
    uint32_t cert_size = read_le32(cert_table_entry_offset() + 4);
    bool has_cert = cert_addr != 0 && cert_size != 0;

    uint64_t write_offset;
    if (!has_cert) {
        // Pad file to 8-byte boundary and append.
        uint64_t aligned = fsize + (8 - fsize % 8) % 8;
        if (aligned > fsize) {
            std::vector<uint8_t> zeros(size_t(aligned - fsize), 0);
            write_at(fsize, zeros.data(), zeros.size());
        }
        write_offset = aligned;
    } else {
        // Overwrite existing certificate table at end of file.
        write_offset = cert_addr;
        // Truncate if the new contents don't reach the old end.
        uint64_t old_end = uint64_t(cert_addr) + cert_size;
        uint64_t new_end = write_offset + win_cert.size();
        if (new_end < old_end)
            file.truncate(new_end);
    }

    // Write the WIN_CERTIFICATE.
    write_at(write_offset, win_cert.data(), win_cert.size());

    // Update data directory entry.
    write_le32(cert_table_entry_offset(), uint32_t(write_offset));
    write_le32(cert_table_entry_offset() + 4, uint32_t(win_cert.size()));

    // Recompute PE checksum.
    recompute_checksum();
}

void PeFile::recompute_checksum()
{
    // IMAGEHLP-compatible checksum algorithm.
    uint64_t fsize = file_size();
    uint64_t cksum_off = checksum_offset();

    // Zero out old checksum first.
    write_le32(cksum_off, 0);

    // Read entire file in 4-byte chunks.
    uint64_t checksum = 0;
    uint8_t buf[65536];
    uint64_t pos = 0;
    while (pos < fsize) {
        size_t to_read = size_t(std::min(uint64_t(sizeof(buf)), fsize - pos));
        // Pad partial final read to 4-byte boundary.
        size_t padded_read = to_read;
        if (padded_read % 4 != 0)
            padded_read += 4 - padded_read % 4;
        memset(buf, 0, padded_read);
        read_at(pos, buf, to_read);

        for (size_t i = 0; i < padded_read; i += 4) {
            if (pos + i == cksum_off)
                continue;  // Skip checksum field.
            uint32_t dword = uint32_t(buf[i]) |
                             (uint32_t(buf[i + 1]) << 8) |
                             (uint32_t(buf[i + 2]) << 16) |
                             (uint32_t(buf[i + 3]) << 24);
            checksum += dword;
            if (checksum > 0xFFFFFFFF)
                checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32);
        }
        pos += to_read;
    }

    // Fold twice to 16 bits, add file length.
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum = (checksum >> 16) + checksum;
    uint32_t result = uint32_t(checksum & 0xFFFF) + uint32_t(fsize);

    write_le32(cksum_off, result);
}

void PeFile::read_at(uint64_t offset, void *buf, size_t len)
{
    file.read_at(offset, buf, len);
}

void PeFile::write_at(uint64_t offset, const void *buf, size_t len)
{
    file.write_at(offset, buf, len);
}

uint32_t PeFile::read_le32(uint64_t offset)
{
    uint8_t b[4];
    read_at(offset, b, 4);
    return uint32_t(b[0]) | (uint32_t(b[1]) << 8) |
           (uint32_t(b[2]) << 16) | (uint32_t(b[3]) << 24);
}

uint16_t PeFile::read_le16(uint64_t offset)
{
    uint8_t b[2];
    read_at(offset, b, 2);
    // Compute in unsigned to avoid int promotion, narrow once at the end.
    return narrow<uint16_t>(uint32_t(b[0]) | (uint32_t(b[1]) << 8));
}

void PeFile::write_le32(uint64_t offset, uint32_t val)
{
    uint8_t b[4] = {
        uint8_t(val), uint8_t(val >> 8),
        uint8_t(val >> 16), uint8_t(val >> 24)
    };
    write_at(offset, b, 4);
}

uint64_t PeFile::file_size()
{
    return file.size();
}
