# Performance configuration

## Native cryptography

The libraries target .NET 8. Set `Settings.Default.UseNativeCrypto = true` for native message cryptography (the default), or `false` for BouncyCastle. Both backends stream large payloads through temporary files. The old signing-only flag has been removed. PKI, timestamp and revocation policy remain shared. See the [migration guide](native-crypto-migration.md) for exact scope, factory overrides and key-provider requirements.

Dispose directly held factory-created sealers/unsealers after active operations finish, using `(instance as IDisposable)?.Dispose()`. Service clients retire and dispose their owned contexts automatically. Caller-owned certificates, stores and WebKeys must outlive active operations.

Native signing, encryption, verification, decryption and completion stream payloads. `InMemorySize` controls when each native stage spills to disk; known large stages start on disk. Native metadata decoding has a separate 16 MiB-per-layer default limit (`MaximumNativeMetadataSize`). Keep admission limits appropriate to the task's memory and temporary-storage budget. See the [streaming measurements](native-streaming-performance.md): allocation fell substantially, with a latency cost in the local profile. The [earlier allocation reductions](native-memory-improvements.md) describe the previous buffered implementation.

Native sealing now pipelines the nested CMS layers in one pass, eliminating its intermediate files and input replay. Unsealing is single-pass as well: the envelope is decrypted while the outer digest is computed, so nothing is spooled before inner verification/output. Payload I/O is asynchronous. Shared signer-key locks cover only the provider signature/verification call; hashing, encryption, copying and network validation do not hold those locks.

The defaults are now a **16 MiB per-stream threshold**, **four shared complete operations**, and a **one-minute deadline**. The [latency/concurrency tuning guide](fargate-latency-tuning.md) contains the measurements for the 4-vCPU/16-GiB target, Server-GC results, and benchmark limits. All three values remain configurable.
## Admission, cancellation and caching

No configuration is required to use the defaults. To override them for the application, configure once at startup:

```csharp
Settings.Default.InMemorySize = 32L * 1024 * 1024;
OperationPolicy.Default = new OperationPolicy(maximumConcurrency: 8, timeout: TimeSpan.FromSeconds(45));
```

Service clients without an explicit override and standalone crypto/PKI entry points use the shared `OperationPolicy.Default`. Its `MaximumConcurrency` and `Timeout` properties expose the configured values. Clients resolve the default for each new call, including clients constructed before startup configuration is applied.

To isolate a group of clients, assign the same custom policy instance to each client's `OperationPolicy` property. An explicit client policy is retained when the global default changes; assigning null restores the shared default. Configure policies before starting work: replacing the global policy does not cancel or migrate requests already running or queued on its predecessor, so replacing it under load can temporarily overlap the two admission budgets.

The deadline includes admission queueing, STS acquisition, encryption, the service request, and response verification. Nested library calls retain the outer admission slot. Tune concurrency and timeout using the application's actual workload; the measurements do not include remote-service waiting time.

Cancellation flows through built-in HTTP and WCF clients. Cancelling a WCF request aborts that client/channel: create a replacement client before another call. Concurrent revocation downloads and token refreshes share work; cancelling one waiter does not cancel other waiters, but the last cancelled waiter aborts the shared operation.

Crypto interfaces retain their existing methods. Cancellation-aware extension overloads accept a token (for example `sealer.SealAsync(input, cancellationToken, recipients)` or `unsealer.UnsealAsync(input, cancellationToken)`). They apply the same shared policy. All seal/unseal/complete/verify entry points use the shared policy and honor an enclosing `OperationScope`, allowing callers to apply a custom policy around an entire workflow. Copy loops check cancellation between pooled-buffer chunks. Native signing and platform chain building cannot be interrupted midway; chain download timeouts are capped to the remaining deadline. Supply intermediates and enable `X509CertificateHelper.DisableCertificateDownloads` when the deployment has the complete chain. Custom timestamp/time-mark providers must cooperate with `OperationScope.Cancellation` to honor cancellation while they run.

Service clients reuse crypto contexts. Replacing the signing certificate, current store or expired-store set, or changing `UseNativeCrypto`, retires the corresponding context after its last active operation. Directly held factory-created contexts retain their original backend; create replacements to switch them. Close or abort clients when finished. Certificates/stores remain owned by the caller and must outlive active operations. Configure these properties before sharing a client; do not mutate its store list concurrently.

Revocation evidence is cached only after validation, keyed by issuer identity and certificate/distribution-point scope. `RevocationCache.EntryLimit` defaults to 1024; `SizeLimitBytes` defaults to 64 MiB of **estimated** retained memory (including a conservative charge for parsed CRLs). Oversized entries are not retained. These limits do not account for in-flight HTTP bodies; admission limits also matter. Inspect `Count` and `EstimatedSizeBytes` alongside actual process memory. The `pharmacy` benchmark suite exercises this cache with eHealth-shaped chains and a Citizen CA CRL the size of the live eID list; see the [benchmark README](../benchmarks/README.md#pharmacy-prescription-retrieval).

SOAP logging emits metadata at Information. Body logging requires both Trace logging and `LoggingEndpointBehavior.LogBodies = true`; `MaxBodyCharacters` defaults to 4096. For signed messages, opt in separately through `EhBinding.Security.LogMessageBodies` and `MaxLoggedBodyCharacters`. Output is truncated, but opt-in inspector tracing still buffers the complete transport message to preserve it for the receiver.

Local regression tests use generated credentials and localhost responders:

```powershell
dotnet build performance-tests/performance-tests.csproj --source https://api.nuget.org/v3/index.json
dotnet test performance-tests/performance-tests.csproj --no-build --no-restore
```

No external eHealth credentials, root-store changes or live eHealth endpoints are needed.

