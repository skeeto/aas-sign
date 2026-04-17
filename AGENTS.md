# Agents

## Overview

aas-sign is a C++ command-line tool that signs PE images (EXE, DLL) using
Azure Artifact Signing (formerly Trusted Signing). It does no local
cryptographic signing -- it computes an Authenticode hash, sends it to
Azure's REST API, assembles the returned signature into a CMS structure,
optionally attaches an RFC 3161 timestamp, and injects the result into the
PE.

## Build

    cmake -B build
    cmake --build build

C++20 (needed for `std::jthread`). Dependencies fetched via CMake
FetchContent (nlohmann/json, mbedTLS on POSIX). Windows uses only system
APIs (BCrypt, WinHTTP). pthreads on POSIX, winpthreads on MinGW.

## Distribution

`.github/action/action.yml` is a composite GitHub Action published from
this same repo.  Consumers reference it as
`skeeto/aas-sign/.github/action@<tag>`.  It downloads the pinned
release binary for the runner OS, resolves an Azure token (either from
the caller or via `az account get-access-token`), and invokes
`aas-sign` with a multi-line `files:` input.  Asset naming convention:
`aas-sign-{linux,windows,macos}-{x86_64,universal}[.exe]`.

## Architecture

```
main.cpp        CLI, worker pool, orchestrates per-file signing flow
pe.cpp          PE parsing, Authenticode hash, checksum, signature injection
der.cpp         DER/ASN.1 encoding primitives (build-and-wrap, no parsing)
cms.cpp         CMS/Authenticode structure assembly (SignedData v1)
x509.cpp        Minimal X.509 parser (issuer DN + serial, CMS cert splitting)
azure.cpp       Azure Trusted Signing REST client (POST + poll loop)
tsa.cpp         RFC 3161 TimeStampReq builder and TimeStampResp parser
base64.cpp      Base64 encode/decode
sha256.hpp      Platform abstraction interface (SHA-256, HTTPS, plain HTTP, File)
posix.cpp       POSIX impl: mbedTLS SHA-256, raw TLS HTTPS, TCP socket HTTP
win32.cpp       Windows impl: BCrypt SHA-256, WinHTTP (TLS + plain)
```

Platform-specific sources are selected by CMake generator expressions.

## Signing flow

1. Parse PE, compute Authenticode SHA-256 (pe.cpp)
2. Build SpcIndirectDataContent + authenticated attributes (cms.cpp)
3. SHA-256 hash the authenticated attrs SET
4. POST hash to Azure, poll for signature + cert chain (azure.cpp)
5. Request RFC 3161 timestamp of the Azure signature (tsa.cpp, optional)
6. Build CMS ContentInfo with SignedData v1, timestamp embedded as
   unsigned attr in SignerInfo (cms.cpp)
7. Wrap in WIN_CERTIFICATE, inject into PE, recompute checksum (pe.cpp)

## Key details and gotchas

- **Authenticode PE hash** excludes three regions: PE checksum (4B at
  peHeaderOffset+88), certificate table data directory entry (8B), and
  existing cert table data.  Unsigned PEs are also padded to an 8-byte
  boundary in the digest.
- **messageDigest attribute** is SHA-256 of the *content* of the
  SpcIndirectDataContent SEQUENCE, not of the SEQUENCE itself (skip the
  tag + length header).  Getting this wrong produces a
  cryptographically-valid-looking signature that Windows silently rejects
  with TRUST_E_NOSIGNATURE.
- **SignedData version** MUST be 1 (not 3) for Authenticode.
- **signatureAlgorithm** in SignerInfo MUST be `rsaEncryption`, not
  `sha256WithRSAEncryption`.
- **SET OF elements** must be sorted lexicographically by encoded bytes
  per DER canonical form.  OpenSSL's PKCS7_verify re-encodes auth attrs
  before hashing, so unsorted order produces a signature mismatch.  See
  `der_set()` in der.cpp.
- **SpcPeImageData** is a fixed constant: flags=empty BIT STRING,
  file=[0] EXPLICIT { [2] EXPLICIT { [0] IMPLICIT BMPString("") } }.
  The [0] EXPLICIT wrapper on `file` is contrary to the ASN.1 spec but
  matches what real-world signed executables use.
- **Azure `signingCertificate`** is double-base64 encoded: the JSON
  string value is base64 text that decodes to MIME base64 text, which in
  turn decodes to a PKCS#7 SignedData wrapper holding the cert chain.
  See azure.cpp and x509.cpp `try_extract_cms_certs()`.
- **RFC 3161 timestamp** attribute OID is `1.3.6.1.4.1.311.3.3.1`
  (szOID_RFC3161_counterSign) -- the Authenticode-specific form, not the
  generic CMS id-aa-signatureTimeStampToken.  The attribute value is the
  full TimeStampToken ContentInfo as returned by the TSA.  It goes in
  unsignedAttrs `[1] IMPLICIT` after the signature OCTET STRING.
- **TSP messageImprint** hashes the contents of the signature OCTET
  STRING, not the OCTET STRING itself.
- **Azure API**: `api-version=2022-06-15-preview`, poll with backoff,
  60s timeout.
- **Default TSA**: `http://timestamp.acs.microsoft.com/timestamping/RFC3161`
  (Microsoft's free service, colocated with Azure Trusted Signing).
  Plain HTTP -- integrity is guaranteed by the TSA's own signature.
- **Concurrency**: `sign_one_file()` is called from worker threads
  (default 8, tunable via `--max-parallel`).  All signing primitives
  (`PeFile`, `azure_sign`, `tsa_timestamp`, `cms_*`) are per-instance or
  create fresh TLS/TCP connections per call, with no shared mutable
  state.  Per-file stderr output is buffered via `FileLogger` and
  flushed as one block under a single mutex so concurrent file
  narratives don't interleave.  Single-file invocations bypass the
  worker pool entirely and write to `std::cerr` directly for identical
  behavior to the pre-concurrency version.
