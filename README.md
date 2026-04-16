# aas-sign

Signs PE images (EXE, DLL) via [Azure Artifact Signing][aas] (formerly
Trusted Signing). No local private key needed -- the tool computes the
Authenticode hash, sends it to Azure, and injects the returned signature
into the PE.

[aas]: https://learn.microsoft.com/en-us/azure/trusted-signing/

## Building

CMake 3.20+, a C++17 compiler. Dependencies are fetched automatically.

    cmake -B build
    cmake --build build

On Windows, only system APIs are used (BCrypt, WinHTTP). On POSIX, mbedTLS
is fetched via FetchContent for TLS and SHA-256.

## Usage

    aas-sign --endpoint <region>.codesigning.azure.net \
             --account <account> \
             --profile <profile> \
             --token <bearer-token> \
             <file.exe|file.dll>

The token can also be set via `AZURE_ACCESS_TOKEN`.

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
    aas-sign --endpoint weu.codesigning.azure.net \
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
   attributes.
3. Send `SHA256(authenticated_attributes)` to the Azure Trusted Signing
   REST API, which returns a raw RSA signature and certificate chain.
4. Assemble a CMS `SignedData` (version 1) `ContentInfo` from the pieces.
5. Wrap it in a `WIN_CERTIFICATE`, append to the PE, update the data
   directory and PE checksum.
