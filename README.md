# aas-sign: Azure Artifact Signing utility

C++20 utility to code-sign PE images (EXE, DLL) via [Azure Artifact
Signing][aas] with no local, private keys. It computes the Authenticode
hash, sends it to Azure, timestamps the returned signature against an
RFC 3161 TSA, and injects the signed CMS into the PE.

## Building

CMake 3.20+, a C++20 compiler. Dependencies are fetched automatically.

    $ cmake -B build
    $ cmake --build build

On Windows, only system APIs are used (BCrypt, WinHTTP). On POSIX, mbedTLS
is fetched via FetchContent for TLS and SHA-256.

## Usage

    $ aas-sign --endpoint <region>.codesigning.azure.net \
               --account <account> \
               --profile <profile> \
               --token <bearer-token> \
               [--timestamp-url <url> | --no-timestamp] \
               [--max-parallel <N>] \
               [--dump-cms <path>] \
               <file.exe|file.dll> [<file.exe|file.dll> ...]

The token can also be set via `AZURE_ACCESS_TOKEN`.

By default, the signature is timestamped against Microsoft's free TSA at
`http://timestamp.acs.microsoft.com/timestamping/RFC3161`.  This is
**strongly recommended** because Azure Trusted Signing issues
short-lived certificates (on the order of days); without a timestamp, the
signature becomes invalid as soon as the signing cert expires.  A
timestamped signature remains verifiable indefinitely.

Use `--timestamp-url` to point at a different RFC 3161 TSA, or
`--no-timestamp` to skip timestamping entirely (not recommended for
production artifacts).

`--dump-cms PATH` writes the raw DER-encoded CMS blob to a file for
inspection (`openssl asn1parse -inform DER -in PATH`).  Only supported
when signing a single file.

### Concurrency

When multiple files are given, they are signed in parallel with up to 8
in flight by default.  Use `--max-parallel N` to change the cap, or
`--max-parallel 1` for fully sequential signing.  The Azure signing API
is async and handles concurrent requests from the same token without
trouble.

In batch mode each file's progress output is prefixed with `[path]` and
buffered, then flushed as a single block when that file finishes, so
concurrent narratives don't interleave.  On completion the tool prints
a summary and exits non-zero if any file failed.

### GitHub Actions

**While the standalone tool works, this GitHub Actions is not ready.**

A composite action is published alongside the tool.  It installs the
pinned release binary for the runner OS, fetches an Azure token (or
accepts one directly), and signs every file you list:

```yaml
- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
- uses: skeeto/aas-sign@v1
  with:
    endpoint: eus.codesigning.azure.net
    account:  myaccount
    profile:  myprofile
    files: |
      dist/myapp.exe
      dist/mylib.dll
      dist/installer.exe
```

Inputs:

| Input           | Required | Default                                      | Notes                                  |
| --------------- | -------- | -------------------------------------------- | -------------------------------------- |
| `endpoint`      | yes      | —                                            | Trusted Signing endpoint host          |
| `account`       | yes      | —                                            | Trusted Signing account                |
| `profile`       | yes      | —                                            | Certificate profile                    |
| `files`         | yes      | —                                            | One path per line; blanks ignored      |
| `token`         | no       | fetched via `az account get-access-token`    | Override bearer token                  |
| `version`       | no       | `v0.1.0`                                     | aas-sign release to install            |
| `timestamp-url` | no       | Microsoft ACS                                | Override RFC 3161 TSA                  |
| `no-timestamp`  | no       | `false`                                      | Set `"true"` to skip timestamping      |
| `max-parallel`  | no       | 8                                            | Concurrent sign operations             |

If you aren't using `azure/login@v2`, pass the bearer token directly
via `token:`.  Whichever form you use, the action masks the token in
the runner log.

## Releases

`.github/workflows/release.yml` builds Linux and Windows binaries,
self-signs the Windows one with the freshly-built Linux one, and
publishes a GitHub release with checksums.  Triggered by pushing a
tag matching `v*`.

The sign-and-release job runs under a GitHub Actions *environment*
called `release`.  Create it at Settings → Environments → New
environment → `release`, then add the secrets and variables there (not
at the repository level).  Using an environment lets the Azure
federated-credential binding match
`repo:<owner>/<repo>:environment:release`, which is more stable than
matching on tag refs.

Required environment configuration (Settings → Environments →
`release`):

| Kind   | Name                       | Purpose                                  |
| ------ | -------------------------- | ---------------------------------------- |
| secret | `AZURE_CLIENT_ID`          | OIDC federated-identity app ID           |
| secret | `AZURE_TENANT_ID`          | Azure tenant                             |
| secret | `AZURE_SUBSCRIPTION_ID`    | Azure subscription                       |
| var    | `TRUSTED_SIGNING_ENDPOINT` | e.g. `eus.codesigning.azure.net`         |
| var    | `TRUSTED_SIGNING_ACCOUNT`  | Trusted Signing account name             |
| var    | `TRUSTED_SIGNING_PROFILE`  | Certificate profile name                 |

The Linux build uses `-static-libstdc++ -static-libgcc` (on top of
dynamic glibc) so the binary survives future GitHub runner image
rotations and runs on any Linux with glibc ≥ 2.39.  The Windows build
cross-compiles with MinGW-w64 on the same Linux runner; no Windows
runner is used.  There is no macOS build — build from source if you
need one.

The release assets are:
- `aas-sign-linux-x86_64`
- `aas-sign-windows-x86_64.exe` (Authenticode-signed by the tool itself)
- `sha256sums.txt`

## How it works

1. Parse the PE and compute its Authenticode SHA-256 hash (excluding the
   checksum field, certificate table directory entry, and any existing
   signature).
2. Build the Authenticode `SpcIndirectDataContent` and CMS authenticated
   attributes (contentType, messageDigest, SPC_STATEMENT_TYPE), sorted in
   DER canonical order.
3. Send `SHA256(authenticated_attributes)` to the Azure Trusted Signing
   REST API, which returns a raw RSA signature and certificate chain.
4. Request an RFC 3161 timestamp over the signature from the TSA.
5. Assemble a CMS `SignedData` (version 1) `ContentInfo` with the Azure
   signature, the cert chain, and the timestamp token embedded as an
   unsigned attribute in the SignerInfo.
6. Wrap it in a `WIN_CERTIFICATE`, append to the PE, update the data
   directory, and recompute the PE checksum.

## Verifying

On Linux/macOS:

    $ osslsigncode verify myapp.exe

On Windows: right-click the file → Properties → Digital Signatures, or
`signtool verify /pa myapp.exe`.


[aas]: https://learn.microsoft.com/en-us/azure/trusted-signing/
