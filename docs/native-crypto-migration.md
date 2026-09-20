# Native cryptography migration (.NET 8)

The production libraries now target **.NET 8** and have no direct or transitive BouncyCastle dependency. RSA/ECDSA signatures, signature verification, AES-CBC, AES key wrapping, CMS, PKCS#12 and RFC 3161 timestamp operations use .NET cryptographic APIs. CRL/OCSP and eHealth CMS envelope fields are decoded with `System.Formats.Asn1`; their cryptographic operations use platform providers.

BouncyCastle remains only in test fixtures/interoperability oracles and the comparison benchmark project. The Java interoperability test project also retains its independent Java implementation. Neither is shipped as a production library dependency.

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

RSA-PSS is always native. `Settings.Default.UseNativeRsaPss` is an obsolete compatibility shim: it returns true, accepts true, and throws if set to false. There is no managed BouncyCastle backend to switch back to. RSA signing requires a platform key provider supporting PSS; verification retains the configured RSA-PKCS#1 and ECDSA eHealth algorithms. Native PSS uses MGF1 with the same digest and a digest-sized salt; unsupported PSS parameter combinations fail validation instead of downgrading algorithms.

PKCS#12 imports preserve named aliases, private-key associations and repeated CA-bag behavior. Password/MAC validation and import limits are provided by the platform loader. Certificates are owned by `EHealthP12`; borrowed certificates must outlive active client operations. Native decryption no longer exports private keys to construct managed key pairs.

System trust remains the default. Applications needing explicit private trust anchors may set `X509CertificateHelper.CustomTrustStore` before starting requests. This does not install certificates in any operating-system store. Do not populate it from an untrusted message; it is application trust configuration.

## Memory behavior

.NET `SignedCms` works with complete message buffers. Public APIs still accept/return streams, and outputs above `Settings.Default.InMemorySize` are stored in temporary files, but that threshold **does not cap internal CMS memory**. This differs from the previous BouncyCastle streaming implementation. Keep admission limits in place and measure large-payload concurrency before deployment. Input lengths beyond the platform's signed 32-bit buffer limit are rejected.

## Validation

The deterministic suite covers:

- Native-to-BouncyCastle and BouncyCastle-to-native CMS round trips.
- RSA-2048/3072, concurrent ECDSA signing, RSA certificate/WebKey recipients and AES-128/192/256 key wrapping.
- B/T/LT/LTA profiles, timestamp verification, completion without changing signatures, and time-mark keys.
- Derived eHealth encryption certificates/ETKs, historical timestamps, PKCS#12 aliases and private keys, and SAML distinguished-name formatting.
- Invalid signatures, trailing data, CRL partitions, cache bounds, cancellation, deadlines, and shared request behavior.
- An assembly-reference assertion that production libraries do not reference BouncyCastle.

The tests use generated credentials, public historical fixtures and localhost responders. They do not exercise live eHealth endpoints or private production credentials. Production and test projects build for .NET 8; comparison dependencies remain confined to tests/benchmarks.

Run:

```powershell
dotnet build ehi.sln --source https://api.nuget.org/v3/index.json
dotnet test performance-tests/performance-tests.csproj --no-build --no-restore
```

For production dependency auditing:

```powershell
dotnet list services/services.csproj package --include-transitive
```

See [performance configuration](performance.md), [matched .NET 8 measurements](native-crypto-performance.md), and [benchmark methodology](../benchmarks/README.md). The earlier [profiling report](performance-profiling.md) is a historical snapshot of the partial migration, not a measurement of this fully native implementation.
