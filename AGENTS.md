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

## Fuzzing

Hand-rolled byte parsers (`pe.cpp`, `x509.cpp`, `tsa.cpp`) have
libFuzzer harnesses under `fuzz/`.  Not built by default.  Linux +
Clang only, with ASan + UBSan + `-D_GLIBCXX_DEBUG`:

    cmake -B build-fuzz -DAAS_SIGN_FUZZ=ON \
        -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
    cmake --build build-fuzz
    ./build-fuzz/fuzz_x509_cert_id -max_total_time=60

Targets: `fuzz_pe`, `fuzz_x509_cert_id`, `fuzz_x509_split_certs`,
`fuzz_der_tlv`, `fuzz_tsa_parse`.  Each harness catches
`std::exception` so the rejection path is not a finding; libFuzzer
only flags sanitizer fires and real crashes.  We assume mbedTLS and
nlohmann/json are fuzzed upstream.

## Distribution

`action.yml` at the repo root is a composite GitHub Action published
from this same repo.  Consumers reference it as
`skeeto/aas-sign@<tag>`.  It downloads the pinned
release binary for the runner OS, resolves an Azure token (either from
the caller or via `az account get-access-token`), and invokes
`aas-sign` with a multi-line `files:` input.  Asset naming convention:
`aas-sign-{linux,windows}-x86_64[.exe]`.

`.github/workflows/release.yml` builds the assets on a `v*` tag push,
self-signs the Windows binary with the freshly-built Linux binary, and
publishes the release with checksums.  No dependency on a previous
release; bootstraps cleanly from the first tag.  No macOS build.

## Architecture

```
main.cpp         CLI + subcommand dispatch + worker pool
pe.cpp           PE parsing, Authenticode hash, checksum, signature injection
der.cpp          DER/ASN.1 encoding primitives (build-and-wrap, no parsing)
cms.cpp          CMS/Authenticode structure assembly (SignedData v1)
x509.cpp         Minimal X.509 parser (issuer DN + serial, CMS cert splitting)
azure.cpp        Azure Trusted Signing REST client (POST + poll loop)
tsa.cpp          RFC 3161 TimeStampReq builder and TimeStampResp parser
oidc.cpp         CI-path OIDC exchange (GitHub Actions runner → Azure token)
auth_laptop.cpp  Laptop-path OAuth login (browser + PKCE) + refresh cache
base64.cpp       Base64 / base64url encode/decode
urlenc.cpp       RFC 3986 percent-encoder
platform.hpp     Platform abstraction interface (everything below)
posix.cpp        POSIX impl: mbedTLS SHA-256, raw TLS HTTPS, TCP sockets,
                 open/pread/pwrite, /dev/urandom, xdg-open
win32.cpp        Windows impl: BCrypt, WinHTTP, WinSock, CreateFileW,
                 ShellExecuteW, SHGetFolderPathW
```

Platform-specific sources are selected by CMake generator expressions.

### Platform-layer paradigm (no #ifdef in feature code)

All OS-specific code — file I/O, sockets, crypto, HTTPS, browser
launch, per-user config directory lookup, atomic file replace, etc. —
lives behind `namespace platform` in `platform.hpp` and is implemented
independently in `posix.cpp` and `win32.cpp`.  Feature modules
(`auth_laptop.cpp`, `pe.cpp`, `cms.cpp`, …) are pure C++17/20 with no
`#ifdef _WIN32` blocks, no `<windows.h>` includes, no POSIX-specific
syscalls.

When adding a new feature that needs OS-specific behaviour, don't
reach for `#ifdef _WIN32` in the feature file.  Extend `platform.hpp`
with a new function or class (follow the `File`, `LoopbackServer`,
`atomic_write_private_file` shape), implement it twice (posix.cpp
and win32.cpp), and call the abstraction from the feature code.
Each implementation handles errors via `throw std::runtime_error`
with a message that includes the path/URL/operation and the
underlying errno / GetLastError in human-readable form.

The payoff: feature modules read cleanly on both platforms, and the
two platform files carry all the "this is how Windows does things"
knowledge in one place where it can be reviewed as a unit.

Console output follows the same rule: feature code never touches
`std::cout` / `std::cerr` / `printf` directly.  Everything bound for
stdout or stderr goes through `platform::write_stdout` /
`platform::write_stderr`, which on Windows detect a console handle and
use `WriteConsoleW` (UTF-8 → UTF-16 transcode) so non-ASCII paths and
identifiers render correctly regardless of the active code page.
Redirected streams get raw UTF-8 bytes — the right thing for
`2> log.txt` and `| tee`.  Feature code composes lines in memory with
`std::ostringstream` or `std::string`, then hands the finished bytes
to the platform API.

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
