# aas-sign: Azure Artifact Signing utility

C++17 utility to code-sign PE images (EXE, DLL) via [Azure Artifact
Signing][aas] with no local, private keys. It computes the Authenticode
hash, sends it to Azure, timestamps the returned signature against an
RFC 3161 TSA, and injects the signed CMS into the PE.

[aas]: https://learn.microsoft.com/en-us/azure/trusted-signing/

## Building

CMake 3.20+, a C++17 compiler. Dependencies are fetched automatically.

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
               [--dump-cms <path>] \
               <file.exe|file.dll>

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
inspection (`openssl asn1parse -inform DER -in PATH`).

### GitHub Actions

```yaml
- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
- run: |
    TOKEN=$(az account get-access-token \
      --resource https://codesigning.azure.net \
      --query accessToken -o tsv)
    aas-sign --endpoint eus.codesigning.azure.net \
             --account myaccount \
             --profile myprofile \
             --token "$TOKEN" \
             myapp.exe
```

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
