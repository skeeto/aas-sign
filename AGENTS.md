# Agents

## Overview

aas-sign is a C++ command-line tool that signs PE images (EXE, DLL) using
Azure Artifact Signing (formerly Trusted Signing). It does no local
cryptographic signing -- it computes an Authenticode hash, sends it to
Azure's REST API, and assembles the returned signature into a CMS structure
injected into the PE.

## Build

    cmake -B build
    cmake --build build

C++17. Dependencies fetched via CMake FetchContent (nlohmann/json, mbedTLS
on POSIX). Windows uses only system APIs (BCrypt, WinHTTP).

## Architecture

```
main.cpp        CLI, orchestrates signing flow
pe.cpp          PE parsing, Authenticode hash, checksum, signature injection
der.cpp         DER/ASN.1 encoding primitives (build-and-wrap, no parsing)
cms.cpp         CMS/Authenticode structure assembly (SignedData v1)
x509.cpp        Minimal X.509 parser (issuer DN + serial extraction)
azure.cpp       Azure Trusted Signing REST client (POST + poll loop)
base64.cpp      Base64 encode/decode
sha256.h        Platform abstraction interface (SHA-256 + HTTPS)
posix.cpp       POSIX impl: mbedTLS SHA-256, raw TLS HTTPS client
win32.cpp       Windows impl: BCrypt SHA-256, WinHTTP HTTPS
```

Platform-specific sources are selected by CMake generator expressions.

## Signing flow

1. Parse PE, compute Authenticode SHA-256 (pe.cpp)
2. Dummy-sign 32 zero bytes to fetch certificate chain (azure.cpp)
3. Build SpcIndirectDataContent + authenticated attributes (cms.cpp)
4. SHA-256 hash the authenticated attrs SET
5. POST hash to Azure, poll for signature (azure.cpp)
6. Build CMS ContentInfo with SignedData v1 (cms.cpp)
7. Wrap in WIN_CERTIFICATE, inject into PE, recompute checksum (pe.cpp)

## Key details

- Authenticode hash excludes: PE checksum (4B at peHeaderOffset+88),
  certificate table data directory entry (8B), and existing cert table data.
- SignedData version MUST be 1 (not 3) for Authenticode compatibility.
- signatureAlgorithm in SignerInfo MUST be rsaEncryption, not sha256WithRSA.
- SpcPeImageData is a fixed constant (flags=empty, file=SpcLink("")).
- Azure API: `api-version=2022-06-15-preview`, poll with backoff, 60s timeout.
