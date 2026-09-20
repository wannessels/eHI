# Performance configuration

## Native cryptography

The libraries target .NET 8. Set `Settings.Default.UseNativeCrypto = true` for native message cryptography (the default), or `false` for BouncyCastle. Both backends stream large payloads through temporary files. The old signing-only flag has been removed. PKI, timestamp and revocation policy remain shared. See the [migration guide](native-crypto-migration.md) for exact scope, factory overrides and key-provider requirements.

Dispose directly held factory-created sealers/unsealers after active operations finish, using `(instance as IDisposable)?.Dispose()`. Service clients retire and dispose their owned contexts automatically. Caller-owned certificates, stores and WebKeys must outlive active operations.

Native signing, encryption, verification, decryption and completion stream payloads. `Settings.Default.InMemorySize` is the per-stream spill threshold: streams above it go to temporary files, and known large stages start there. It defaults to `long.MaxValue`, so nothing spills and no temporary file is created unless the application sets a finite size at startup (the temporary-file path costs about twice the CPU per request). In-memory spools take 256 KiB blocks from a pool (`Microsoft.IO.RecyclableMemoryStream`; returned blocks are zeroed), so large messages no longer allocate payload-sized arrays on the large-object heap; `Settings.Default.SpoolPoolBytes` (256 MiB by default, read at first use) caps the freed memory the pool keeps, and the gauges `ehealth.spool.pool.bytes` and `ehealth.spool.pool.free.bytes` show what is in use and retained. Native metadata decoding has a separate 16 MiB-per-layer default limit (`MaximumNativeMetadataSize`). Keep admission limits appropriate to the task's memory and temporary-storage budget. See the [streaming measurements](native-streaming-performance.md): allocation fell substantially, with a latency cost in the local profile. The [earlier allocation reductions](native-memory-improvements.md) describe the previous buffered implementation.

Native sealing now pipelines the nested CMS layers in one pass, eliminating its intermediate files and input replay. Unsealing is single-pass as well: the envelope is decrypted while the outer digest is computed, so nothing is spooled before inner verification/output. Payload I/O is asynchronous. Each signing certificate or WebKey has a pool of up to `Settings.Default.SigningKeyHandles` private-key handles (the processor count by default), opened on demand, so concurrent seals sign in parallel instead of serializing on one handle; set it to 1 for keys that cannot be used concurrently, such as smart cards. A WebKey whose key cannot be exported keeps its single shared handle. WS-Security request signing in the service clients leases from the same per-certificate pool (`SigningKeyPool`, limit `SigningKeyPool.DefaultLimit`, the same value as `SigningKeyHandles`) instead of opening a key handle per message, and the X.509 BinarySecurityToken is built once per certificate. The histogram `ehealth.signing.queue.duration` shows time spent waiting for a handle.

The defaults are now **no spill threshold** (everything stays in memory), **four shared complete operations**, and a **one-minute deadline**. The [latency/concurrency tuning guide](fargate-latency-tuning.md) contains the measurements for the 4-vCPU/16-GiB target, Server-GC results, and benchmark limits. All three values remain configurable.
## Metrics

The libraries publish metrics through `System.Diagnostics.Metrics` on the meter `Egelke.EHealth` (`EHealthMetrics.MeterName`). Nothing leaves the process unless the application subscribes.

| Instrument | Type | Tags | Meaning |
|---|---|---|---|
| `ehealth.operations` | counter | `operation`, `outcome` | Completed top-level operations: `seal`, `unseal`, `verify`, `complete`, `chain`, `timestamp`, or the WCF port type name of a service call; outcome `ok`, `error` or `cancelled` |
| `ehealth.operation.duration` | histogram, ms | `operation`, `outcome` | Duration including admission wait |
| `ehealth.operation.queue.duration` | histogram, ms | `operation` | Time spent waiting for an admission slot |
| `ehealth.operations.active` | up-down counter | `operation` | Admitted operations in progress |
| `ehealth.chain.builds` | counter | `source` = `cache` or `platform` | Certificate paths served |
| `ehealth.chain.build.duration` | histogram, ms | `source` | Platform chain build time |
| `ehealth.revocation.downloads`, `.duration`, `.bytes` | counter, histogram, counter | `type` = `crl` or `ocsp`, `outcome` | Evidence downloads |
| `ehealth.sts.requests`, `.duration` | counter, histogram | `type` = `issue` or `renew`, `outcome` | SAML token requests |
| `ehealth.timestamp.requests`, `.duration` | counter, histogram | `outcome` | RFC 3161 requests |
| `ehealth.spools`, `ehealth.spool.bytes` | counters | `storage` = `memory` or `file` | Payload spools created and bytes written to them |
| `ehealth.spool.spills` | counter | | Spools that outgrew `InMemorySize` and moved to a temporary file |
| `ehealth.spool.pool.bytes`, `.free.bytes` | observable gauges | | Pooled spool memory in use and kept for reuse |
| `ehealth.signing.queue.duration` | histogram, ms | | Time waiting for a private-key handle before signing |
| `ehealth.revocation.cache.entries`, `.bytes`, `ehealth.chain.cache.entries`, `ehealth.certificate.cache.entries`, `ehealth.key.cache.entries` | observable gauges | | Cache sizes |

A nested call (a chain build inside an unseal, a timestamp inside a seal, the STS inside a service call) is part of the enclosing operation; only the dedicated instruments above count it separately. Queue duration above a few milliseconds means `OperationPolicy` concurrency is the bottleneck; `platform` chain builds and evidence downloads should stay rare once the caches are warm.

To reach CloudWatch, subscribe with OpenTelemetry and export OTLP to the AWS Distro for OpenTelemetry collector, whose `awsemf` exporter writes CloudWatch metrics, or to the CloudWatch agent's OTLP endpoint:

```csharp
services.AddOpenTelemetry().WithMetrics(metrics => metrics
    .AddMeter(EHealthMetrics.MeterName)
    .AddOtlpExporter());
```

Locally, `dotnet-counters monitor --counters Egelke.EHealth --process-id <pid>` shows the same instruments, and a `MeterListener` works without any package.

## Admission, cancellation and caching

No configuration is required to use the defaults. To override them for the application, configure once at startup:

```csharp
Settings.Default.InMemorySize = 64L * 1024 * 1024; // spill streams above 64 MiB to temporary files; the default never spills
OperationPolicy.Default = new OperationPolicy(maximumConcurrency: 8, timeout: TimeSpan.FromSeconds(45));
```

Service clients without an explicit override and standalone crypto/PKI entry points use the shared `OperationPolicy.Default`. Its `MaximumConcurrency` and `Timeout` properties expose the configured values. Clients resolve the default for each new call, including clients constructed before startup configuration is applied.

To isolate a group of clients, assign the same custom policy instance to each client's `OperationPolicy` property. An explicit client policy is retained when the global default changes; assigning null restores the shared default. Configure policies before starting work: replacing the global policy does not cancel or migrate requests already running or queued on its predecessor, so replacing it under load can temporarily overlap the two admission budgets.

The deadline includes admission queueing, STS acquisition, encryption, the service request, and response verification. Nested library calls retain the outer admission slot. Tune concurrency and timeout using the application's actual workload; the measurements do not include remote-service waiting time.

Cancellation flows through built-in HTTP and WCF clients. Cancelling a WCF request aborts that client/channel: create a replacement client before another call. Concurrent revocation downloads and token refreshes share work; cancelling one waiter does not cancel other waiters, but the last cancelled waiter aborts the shared operation.

Crypto interfaces retain their existing methods. Cancellation-aware extension overloads accept a token (for example `sealer.SealAsync(input, cancellationToken, recipients)` or `unsealer.UnsealAsync(input, cancellationToken)`). They apply the same shared policy. All seal/unseal/complete/verify entry points use the shared policy and honor an enclosing `OperationScope`, allowing callers to apply a custom policy around an entire workflow. Copy loops check cancellation between pooled-buffer chunks. Native signing and platform chain building cannot be interrupted midway; chain download timeouts are capped to the remaining deadline. Supply intermediates and enable `X509CertificateHelper.DisableCertificateDownloads` when the deployment has the complete chain. Custom timestamp/time-mark providers must cooperate with `OperationScope.Cancellation` to honor cancellation while they run.

Service clients reuse crypto contexts. Replacing the signing certificate, current store or expired-store set, or changing `UseNativeCrypto`, retires the corresponding context after its last active operation. Directly held factory-created contexts retain their original backend; create replacements to switch them. Close or abort clients when finished. Certificates/stores remain owned by the caller and must outlive active operations. Configure these properties before sharing a client; do not mutate its store list concurrently.

Revocation evidence is cached only after validation, keyed by issuer identity and certificate/distribution-point scope. `RevocationCache.EntryLimit` defaults to 1024; `SizeLimitBytes` defaults to 256 MiB of **estimated** retained memory: the encoded evidence plus about 128 bytes per revoked entry for parsed CRLs, so a Citizen CA list of 350,000 entries is charged about 57 MiB. Oversized entries are not retained. These limits do not account for in-flight HTTP bodies; admission limits also matter.

Successful platform chain builds are cached by the leaf and extra-store certificate thumbprints for `ChainCache.Lifetime` (ten minutes by default; zero disables it) and reused only while every certificate in the path is valid at the requested time; a path with any error status is rebuilt each time. Revocation is checked separately, so cached paths carry no revocation state. Assigning `X509CertificateHelper.CustomTrustStore` or `DisableCertificateDownloads` clears the cache, as does `ChainCache.Clear()`; `Count` and `EntryLimit` (1024) are exposed.

Certificates embedded in CMS messages are decoded once per distinct encoding and served as handle copies from `CertificateCache` (`EntryLimit` 4096, `Count`, `Clear()`), because decoding a certificate on OpenSSL costs about 0.45 ms and a copy about 2 µs. Copies are independent: disposing one never affects another. Public keys are constructed once per certificate thumbprint and shared from `PublicKeyCache` (`EntryLimit` 4096) for signature verification and recipient key transport, and RSA and DSA key sizes are read from the certificate's key encoding instead of constructing a key, because every key construction path costs about 0.38 ms on OpenSSL. Inspect `Count` and `EstimatedSizeBytes` alongside actual process memory. The `pharmacy` benchmark suite exercises this cache with eHealth-shaped chains and a Citizen CA CRL the size of the live eID list; see the [benchmark README](../benchmarks/README.md#pharmacy-prescription-retrieval).

SOAP logging emits metadata at Information. Body logging requires both Trace logging and `LoggingEndpointBehavior.LogBodies = true`; `MaxBodyCharacters` defaults to 4096. For signed messages, opt in separately through `EhBinding.Security.LogMessageBodies` and `MaxLoggedBodyCharacters`. Output is truncated, but opt-in inspector tracing still buffers the complete transport message to preserve it for the receiver.

Local regression tests use generated credentials and localhost responders:

```powershell
dotnet build performance-tests/performance-tests.csproj --source https://api.nuget.org/v3/index.json
dotnet test performance-tests/performance-tests.csproj --no-build --no-restore
```

No external eHealth credentials, root-store changes or live eHealth endpoints are needed.

