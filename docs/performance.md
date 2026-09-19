# Performance configuration

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

Service clients reuse crypto contexts. Replacing the signing certificate, current store or expired-store set retires the corresponding context after its last active operation. Close or abort clients when finished. Certificates/stores remain owned by the caller and must outlive active operations. Configure these properties before sharing a client; do not mutate its store list concurrently.

Revocation evidence is cached only after validation, keyed by issuer identity and certificate/distribution-point scope. `RevocationCache.EntryLimit` defaults to 1024; `SizeLimitBytes` defaults to 64 MiB of **estimated** retained memory (including a conservative charge for parsed CRLs). Oversized entries are not retained. These limits do not account for in-flight HTTP bodies; admission limits also matter. Inspect `Count` and `EstimatedSizeBytes` alongside actual process memory.

SOAP logging emits metadata at Information. Body logging requires both Trace logging and `LoggingEndpointBehavior.LogBodies = true`; `MaxBodyCharacters` defaults to 4096. For signed messages, opt in separately through `EhBinding.Security.LogMessageBodies` and `MaxLoggedBodyCharacters`. Output is truncated, but opt-in inspector tracing still buffers the complete transport message to preserve it for the receiver.

Local regression tests use generated credentials and localhost responders:

```powershell
dotnet build performance-tests/performance-tests.csproj --source https://api.nuget.org/v3/index.json
dotnet test performance-tests/performance-tests.csproj --no-build --no-restore
```

No external eHealth credentials, root-store changes or live eHealth endpoints are needed.

