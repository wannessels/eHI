# Performance configuration

## Native cryptography

The libraries target .NET 8. Set `Settings.Default.UseNativeCrypto = true` for native message cryptography (the default), or `false` for BouncyCastle. Both backends stream large payloads through temporary files. The old signing-only flag has been removed. PKI, timestamp and revocation policy remain shared. See the [migration guide](native-crypto-migration.md) for exact scope, factory overrides and key-provider requirements.

Dispose directly held factory-created sealers/unsealers after active operations finish, using `(instance as IDisposable)?.Dispose()`. Service clients retire and dispose their owned contexts automatically. Caller-owned certificates, stores and WebKeys must outlive active operations.

Native signing, encryption, verification, decryption and completion stream payloads. `InMemorySize` controls when each native stage spills to disk; known large stages start on disk. Native metadata decoding has a separate 16 MiB-per-layer default limit (`MaximumNativeMetadataSize`). Keep admission limits appropriate to the task's memory and temporary-storage budget. See the [streaming measurements](native-streaming-performance.md): allocation fell substantially, with a latency cost in the local profile. The [earlier allocation reductions](native-memory-improvements.md) describe the previous buffered implementation.
## Admission, cancellation and caching

Use one shared policy for clients belonging to the same application capacity budget:

```csharp
var policy = new OperationPolicy(maximumConcurrency: 16, timeout: TimeSpan.FromSeconds(45));
mda.OperationPolicy = policy;
kgss.OperationPolicy = policy;
var result = await mda.ConsultAsync(query, etee: true, cancellationToken: cancellationToken);
```

The default is 16 complete operations per process with a one-minute deadline. The deadline includes admission queueing, STS acquisition, encryption, the service request, and response verification. Nested library calls retain the outer admission slot. Tune concurrency and timeout using the application workload and container CPU/memory budget; these defaults are not a Fargate sizing recommendation.

Cancellation flows through built-in HTTP and WCF clients. Cancelling a WCF request aborts that client/channel: create a replacement client before another call. Concurrent revocation downloads and token refreshes share work; cancelling one waiter does not cancel other waiters, but the last cancelled waiter aborts the shared operation.

Crypto interfaces retain their existing methods. Cancellation-aware extension overloads accept a token (for example `sealer.SealAsync(input, cancellationToken, recipients)` or `unsealer.UnsealAsync(input, cancellationToken)`). They apply the same shared policy. All seal/unseal/complete/verify entry points use the shared policy and honor an enclosing `OperationScope`, allowing callers to apply a custom policy around an entire workflow. Copy loops check cancellation between pooled-buffer chunks. Native signing and platform chain building cannot be interrupted midway; chain download timeouts are capped to the remaining deadline. Supply intermediates and enable `X509CertificateHelper.DisableCertificateDownloads` when the deployment has the complete chain. Custom timestamp/time-mark providers must cooperate with `OperationScope.Cancellation` to honor cancellation while they run.

Service clients reuse crypto contexts. Replacing the signing certificate, current store or expired-store set, or changing `UseNativeCrypto`, retires the corresponding context after its last active operation. Directly held factory-created contexts retain their original backend; create replacements to switch them. Close or abort clients when finished. Certificates/stores remain owned by the caller and must outlive active operations. Configure these properties before sharing a client; do not mutate its store list concurrently.

Revocation evidence is cached only after validation, keyed by issuer identity and certificate/distribution-point scope. `RevocationCache.EntryLimit` defaults to 1024; `SizeLimitBytes` defaults to 64 MiB of **estimated** retained memory (including a conservative charge for parsed CRLs). Oversized entries are not retained. These limits do not account for in-flight HTTP bodies; admission limits also matter. Inspect `Count` and `EstimatedSizeBytes` alongside actual process memory.

SOAP logging emits metadata at Information. Body logging requires both Trace logging and `LoggingEndpointBehavior.LogBodies = true`; `MaxBodyCharacters` defaults to 4096. For signed messages, opt in separately through `EhBinding.Security.LogMessageBodies` and `MaxLoggedBodyCharacters`. Output is truncated, but opt-in inspector tracing still buffers the complete transport message to preserve it for the receiver.

Local regression tests use generated credentials and localhost responders:

```powershell
dotnet build performance-tests/performance-tests.csproj --source https://api.nuget.org/v3/index.json
dotnet test performance-tests/performance-tests.csproj --no-build --no-restore
```

No external eHealth credentials, root-store changes or live eHealth endpoints are needed.

