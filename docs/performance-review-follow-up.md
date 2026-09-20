# Performance review follow-up

The review compared `perf-fixes` at `13e475e` with `master` at `3e7f0fd`. Findings 1–4 and the `level = null` revocation regression have now been addressed as follows. Previous runtime targets have also been restored with [CI coverage](runtime-support.md). Public PKI/interface migration changes remain; see the [migration guide](native-crypto-migration.md).

| Finding | Resolution | Remaining limit or tradeoff |
|---|---|---|
| **1. Unbounded in-memory payload spools by default** | Default spill threshold is **16 MiB per stream**. Larger streams use temporary files, including when input length is unknown. | This is not a process-memory or total-message-size limit. Budget temporary storage and enforce input-size limits at the application boundary. |
| **2. Stale cached trust / ineffective cache disablement** | Cache keys include a snapshot of custom trust anchors and download policy. Lifetime zero disables lookup and insertion. Clearing replaces the cache generation so earlier builds cannot repopulate the active cache. | System-trust paths are rebuilt by the platform on every call, which costs more than returning a cached successful path. |
| **3. Expired recipient selected despite a valid alternative** | Both backends select across matching recipient entries at the signing time. Native mode also checks that the selected identity unwraps the content key actually used to decrypt. | Ambiguous entries with different content keys are rejected by native mode; the single-pass pipeline is retained for normal messages. |
| **4. PKCS#1-only signing providers lose support** | Native CMS signing now supports explicitly selected RSA-PKCS#1 v1.5 without exporting the private key. PSS remains the default. | The receiving service must accept PKCS#1 signatures. No library can provide PSS through a non-exportable key's PKCS#1-only signing API. |
| **`level = null` bypasses revocation** | Null level now checks signer revocation, including embedded evidence and downloads when necessary, on both backends. | Null still does not require a timestamp. Missing revocation evidence cannot establish full signer trust. |

## Memory defaults

The shared defaults are a **16 MiB per-stream spill threshold**, **four complete operations**, and a **one-minute cooperative deadline**. Pooled memory is still used below the threshold; returned blocks are zeroed. The pool's 256 MiB free-memory budget limits retained free blocks, not memory held by active operations.

Typical prescription payloads and 8 MiB payloads can stay in memory. Streams that grow beyond 16 MiB spill to temporary files. These may contain plaintext while an unseal is in progress, so use a suitably protected temporary directory with enough disk capacity. Files are opened for deletion on close. CMS metadata has its separate 16 MiB per-layer limit.

Configure before serving requests:

```csharp
Settings.Default.InMemorySize = 16L * 1024 * 1024; // The default.
```

Applications can explicitly opt out of spilling with `long.MaxValue`, but must then supply their own adequate memory/input-size bounds. The older benchmark results record their original thresholds and have not been remeasured as part of this fix.

## Trust-cache behavior

Successful paths are cached only with an explicit `X509CertificateHelper.CustomTrustStore`. The key includes leaf, extra-store and trust-anchor thumbprints plus the certificate-download setting. Removing a root from the configured collection between operations therefore stops matching the old cached path. Each platform build uses the same collection snapshots used to construct its key.

Setting `ChainCache.Lifetime = TimeSpan.Zero` disables reuse immediately and clears existing entries. `ChainCache.Clear()`, trust-store assignment and download-policy changes replace the cache generation. A build using an earlier generation cannot insert into the new generation.

With `CustomTrustStore = null`, each call asks the platform to build and validate the path. This avoids adding the library's ten-minute stale-trust window after an OS trust change. It does not override the OS/runtime's own trust-store refresh behavior. Certificate decoding, public-key and validated revocation-evidence caches remain available in both modes. The extra platform work can reduce performance for applications using system trust; the custom-trust pharmacy benchmark does not measure that cost.

Configure trust before serving requests. Do not mutate a certificate collection concurrently with validation. Operations already in progress use their captured configuration; drain them before an emergency trust update if they must not finish under the old configuration. Using custom trust just to enable caching changes the source of trust: applications must own and update those anchors deliberately.

## Recipient selection after rotation

All matching recipient entries are considered, preferring a certificate valid at the outer signing time and then the newer valid certificate. Historical messages can therefore use an expired-today certificate that was valid when the message was signed.

BouncyCastle selects before decryption because it already has the outer signature information. Native mode provisionally decrypts while reading the outer signed payload. After verifying the outer signature and obtaining the signing time, it selects across the preserved recipient entries. If that selects a different entry, its private key must unwrap the same AES content key used for decryption. The temporary recovered keys are cleared afterwards. A different key causes failure rather than relabelling plaintext as belonging to another recipient. The returned subject identifier is updated to match the selected certificate.

## PKCS#1-only RSA signing providers

**Finding 4 was fixable without reverting the native migration.** Select PKCS#1 explicitly for a provider that lacks PSS when the receiving profile permits it:

```csharp
using System.Security.Cryptography;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Sender;

// Pin a factory without changing the process-wide default.
var factory = new DataSealerFactory(
    loggerFactory,
    useNativeCrypto: true,
    rsaSignaturePadding: RSASignaturePadding.Pkcs1);
var sealer = factory.Create(Level.B_Level, signingCertificate);

// Alternatively, configure the default for newly created sealers/service contexts.
Settings.Default.RsaSignaturePadding = RSASignaturePadding.Pkcs1;
// For a device that cannot sign concurrently:
Settings.Default.SigningKeyHandles = 1;
```

`EhDataSealerFactory` accepts the same padding override. A null override follows `Settings.Default.RsaSignaturePadding` at each `Create` call. Created sealers retain their choice. Service clients include padding in their context-cache identity, so changing the default replaces the context for subsequent encryption calls while existing operations finish with their original choice.

Native mode calls the key provider with the selected padding, without private-key export. CMS encodes the corresponding signature algorithm. BouncyCastle also honors the padding choice, but that backend still requires exporting private-key material. ECDSA and SOAP WS-Security signing are unaffected. Signature, certificate, key-usage, key-size, timestamp and revocation checks remain enabled.

| RSA key/provider | Native PSS, the default | Native explicit PKCS#1 | BouncyCastle |
|---|---|---|---|
| Exportable key | Requires PSS support in the effective signing handle | Requires PKCS#1 support | Uses exported key material with the selected padding |
| Non-exportable, PSS-capable | Supported | Supported if the provider also implements PKCS#1 | Unsupported: requires export |
| Non-exportable, PKCS#1-only | Unsupported | **Supported** | Unsupported: requires export |

There is no automatic padding fallback on a cryptographic exception: it may indicate an unrelated provider failure. If a receiving service mandates PSS and the non-exportable key's provider cannot perform PSS, use a PSS-capable provider/device. A setting cannot add an unavailable hardware operation. Some exportable platform WebKeys are cloned to software handles; that does not solve the non-exportable case.

Tests use a provider that rejects private-key export and PSS signing, verify the result through both backends, and check that PSS failures do not silently switch padding. Physical eID/CSP/CNG/HSM and live service interoperability still require validation in the intended deployment.

## Null-level revocation

`DataVerifierFactory.Create(null)` and `DataUnsealerFactory.Create(null, ...)` now retain master's signer-revocation checks. Both process embedded CRL/OCSP evidence and fetch applicable evidence when needed. A revoked signer is untrusted; lack of evidence produces an unknown trust result rather than full trust. A timestamp remains optional. Service-client validation/trust gates and the separate `EncryptionToken.Verify(false)` API keep their existing behavior.

The regression tests cover downloaded and embedded CRLs on both backends, full unsealing of a revoked signer, certificate rotation in either recipient order at current/historical times, recipient-to-content-key binding, warmed-cache invalidation, a trust update during a build, explicit padding and context replacement, and default spilling above 16 MiB.
