# Native cryptography migration (.NET 8)

The production libraries target **.NET 8**. Native .NET message cryptography is the default, with a selectable BouncyCastle streaming backend. Public interfaces retain the native migration's PKI types; switching the backend does not change the API or wire format.

BouncyCastle.Cryptography is a production dependency of `etee-crypto` again, including when native mode is selected. PKI and transport libraries do not directly reference it. The Java interoperability test project retains its independent implementation.

## Backend selection

```csharp
Settings.Default.UseNativeCrypto = true;  // Native .NET (default)
Settings.Default.UseNativeCrypto = false; // BouncyCastle streaming
```

All sealer, unsealer, verifier and completer factories capture the current value at each `Create` call. Existing instances retain their implementation. Service clients include the flag in their context-cache keys: the next encryption/decryption call uses the new setting, while active operations finish before their old context is disposed. Messages from either backend can be read by either backend.

For concurrent comparisons without changing global configuration, every factory also accepts a fixed override:

```csharp
var factory = new DataSealerFactory(loggerFactory, useNativeCrypto: false);
```

The switch covers RSA-PSS/ECDSA message signing and verification, AES-CBC content encryption/decryption, RSA/AES recipient key wrapping, and streaming CMS construction/parsing/completion. Both implementations share signature metadata handling and certificate, timestamp and revocation policy. PKCS#12 loading, ETK parsing, CRL/OCSP, RFC 3161 and SOAP/STS stay on the current platform implementation; this is not a rollback of the entire PKI migration.

BouncyCastle mode exports private keys into managed key parameters. Use native mode for non-exportable keys or hardware key providers. There is no automatic fallback between backends. Both modes keep the existing admission and cancellation policy; individual cryptographic primitive calls cannot be interrupted midway.

## Compatibility changes

This is a breaking migration: .NET Framework 4.6.2, .NET Standard 2.0 and .NET 6 library targets have been removed. The existing seal/unseal/service interfaces remain, but public PKI methods no longer expose BouncyCastle types.

| Previous type/API | Replacement |
|---|---|
| `Org.BouncyCastle.Asn1.X509.CertificateList` | `Egelke.EHealth.Client.Pki.CertificateRevocationList` |
| `CertificateList.GetInstance(...)` | `CertificateRevocationList.Parse(derBytes)` |
| OCSP `BasicOcspResponse` / outer `OcspResponse` | `Egelke.EHealth.Client.Pki.OcspResponse` |
| OCSP ASN.1 wrapper extraction | `OcspResponse.Parse(bytes)` accepts a successful HTTP response or a basic response |
| `TbsResponseData.ProducedAt.ToDateTime()` | `ProducedAt` |
| CRL `ThisUpdate.ToDateTime()` / `NextUpdate.ToDateTime()` | `ThisUpdate` / nullable `NextUpdate` |
| BouncyCastle `TimeStampToken` | `System.Security.Cryptography.Pkcs.Rfc3161TimestampToken` |
| `TimeStampInfo.GenTime` | `TokenInfo.Timestamp.UtcDateTime` |

`ToTimeStampToken`, `IsMatch`, `Validate` and `ValidateAsync` remain extension methods in the PKI namespace. Revocation lists passed to chain/timestamp verification must use the new evidence types. `GetEncoded()` returns DER evidence suitable for CAdES attributes.

The old signing-only flag has been removed. Use `Settings.Default.UseNativeCrypto` to select the **whole message backend**. Native RSA signing requires a platform key provider supporting PSS; verification retains the configured RSA-PKCS#1 and ECDSA eHealth algorithms. Native PSS uses MGF1 with the same digest and a digest-sized salt; unsupported PSS parameter combinations fail validation instead of downgrading algorithms.

PKCS#12 imports preserve named aliases, private-key associations and repeated CA-bag behavior. Password/MAC validation and import limits are provided by the platform loader. Certificates are owned by `EHealthP12`; borrowed certificates must outlive active client operations. Native decryption no longer exports private keys to construct managed key pairs.

System trust remains the default. Applications needing explicit private trust anchors may set `X509CertificateHelper.CustomTrustStore` before starting requests. This does not install certificates in any operating-system store. Do not populate it from an untrusted message; it is application trust configuration.

## Memory behavior

Native mode now streams payloads through incremental hashing, platform RSA/ECDSA signatures and native AES `CryptoStream` transforms. Its CMS framing reader accepts definite DER and chunked/indefinite BER payloads without flattening the full content. Platform `SignedCms` is used only for bounded signature metadata and the shared validation/completion policy. Legacy signatures without signed attributes also verify incrementally in native mode.

Native sealing is a single-pass pipeline: plaintext flows through inner hashing/signing, AES encryption and outer hashing/signing into the final result. Non-seekable input is not spooled or replayed, including during an outer-signature retry. Output uses standard chunked BER CMS. Unsealing is a single pass as well: the encrypted envelope streams through the outer digest and decryption into inner verification and final output without an intermediate spool. The outer signature is verified once the whole message has been read, the recipient certificate reported in the result is selected afterwards by the validated signing time, and every status check still gates the returned plaintext.

Each retained native stage/output spills to a temporary file above `Settings.Default.InMemorySize` (16 MiB by default), with known large stages starting on disk. Override this value at application startup to change the memory allowance. Payload copies and native temporary-file I/O are asynchronous; small ASN.1 framing/metadata operations and cryptographic primitives still run synchronously. Caller streams stay open, returned streams belong to the caller, and failed/cancelled operations dispose their temporary streams. Completed unseal results retain the existing security-status API: callers must check validation/trust status before using plaintext.

`Settings.Default.MaximumNativeMetadataSize` limits aggregate decoded metadata to 16 MiB per CMS layer, excluding payloads. BER nesting is limited to 32 levels. Certificates, CRLs/OCSP and timestamps still consume memory, and each active operation has its own buffers and temporary stages; the stream threshold is not a process-memory cap. Native CMS no longer imposes a whole-payload 32-bit array limit. The native eHealth profile rejects CMS countersignatures rather than silently omitting their validation; supported signature timestamps continue through the existing timestamp policy.

BouncyCastle mode streams payloads through signatures and encryption, using temporary intermediate files above the threshold. Only detached signature metadata (including certificates and revocation evidence) passes through the shared platform CMS policy. Non-seekable inputs are first spooled to a temporary file. Legacy signatures without signed attributes require buffered BouncyCastle verification; newly sealed messages always include signed attributes. The threshold is a buffering choice, not a hard bound on process memory. Keep admission limits in place and measure large-payload concurrency before deployment.

## Validation

The deterministic suite covers:

- Native-to-BouncyCastle and BouncyCastle-to-native CMS round trips.
- RSA-2048/3072, concurrent ECDSA signing, RSA certificate/WebKey recipients and AES-128/192/256 key wrapping.
- B/T/LT/LTA profiles, timestamp verification, completion without changing signatures, and time-mark keys.
- Derived eHealth encryption certificates/ETKs, historical timestamps, PKCS#12 aliases and private keys, and SAML distinguished-name formatting.
- Invalid signatures, trailing data, CRL partitions, cache bounds, cancellation, deadlines, and shared request behavior.
- Backend selection, pinned factories, large-message streaming, non-seekable inputs, and changed content in either signature layer.
- An assembly-reference assertion that PKI and transport remain independent of BouncyCastle.

The tests use generated credentials, public historical fixtures and localhost responders. They do not exercise live eHealth endpoints or private production credentials. Production and test projects build for .NET 8.

Run:

```powershell
dotnet build ehi.sln --source https://api.nuget.org/v3/index.json
dotnet test performance-tests/performance-tests.csproj --no-build --no-restore
```

For production dependency auditing:

```powershell
dotnet list services/services.csproj package --include-transitive
```

See [performance configuration](performance.md), [current latency/concurrency measurements](fargate-latency-tuning.md), and [benchmark methodology](../benchmarks/README.md). The earlier [staged streaming measurements](native-streaming-performance.md), [buffered memory improvements](native-memory-improvements.md), [backend comparison](backend-crypto-performance.md), [native migration comparison](native-crypto-performance.md), and [profiling report](performance-profiling.md) are historical snapshots.
