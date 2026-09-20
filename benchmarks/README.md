# Reproducible performance profiles

The harness measures platform/managed signing primitives and production CMS operations, a standalone stream-pooling prototype, and localhost HTTPS connection reuse. It never calls live eHealth services or installs trust roots.

## Run

.NET 8 SDK is required. A local optimized run:

```powershell
dotnet build benchmarks/benchmarks.csproj -c Release -p:SignAssembly=false --source https://api.nuget.org/v3/index.json
dotnet benchmarks/bin/Release/net8.0/benchmarks.dll --output artifacts/profiling/local.json
```

Release signing is disabled only for the benchmark build because the private release signing key is not part of the repository.

For a pinned Linux environment with one CPU and 1 GiB memory:

```powershell
./benchmarks/run-linux.ps1
./benchmarks/run-linux.ps1 -DisableTiering
```

The script mounts the repository read-only, builds a disposable copy in the container, and writes results/logs under `artifacts/profiling`. Docker Desktop must be running. The SDK image digest is pinned in the script. `-Suite crypto`, `-Suite memory`, and `-Suite http` select components; `-Quick` is a smoke check, not a performance result. Re-running overwrites the scratch result for that mode.

The executable also accepts `--suite crypto|memory|http|all`, `--quick`, and `--output path`.

## Method

Each scenario performs five unmeasured warm-up operations, followed by three measurement rounds. GC is forced between rounds. Reported summaries use the median of the three round means, not a pooled request percentile. Each JSON row retains its own mean, p50/p95, allocations, CPU time and collection counts. Peak working set is cumulative for the process, not a per-case peak. Process-wide allocation measurements include both client and server for HTTP.

- Signing: 200 operations per round, RSA-2048/3072, 64 B/256 KiB input. Key generation/export and factory creation happen outside measurement. The platform case uses RSA.SignData with PSS; it includes hashing plus signing. Generated signatures are checked before measurement.
- CMS: production B-level seal/unseal with a reused RSA-2048 WebKey signer and AES-128 shared recipient key. Payloads are 32 KiB, 1 MiB, 1 MiB + 1 B and 8 MiB. Each round uses 40 operations through 1 MiB and 12 above it. Signature validity, decoded length and the final payload byte are checked. No certificate revocation, STS/TSA calls or SOAP transport are part of this case. CMS scenarios measure both selectable production backends using pinned factories; older committed results retain the former partial-migration variants. The alternative memory threshold is 64 MiB versus the 1 MiB default.
- Streams: three temporary streams, three copies and a final `ToArray`, with 150 iterations through 1 MiB and 40 at 8 MiB. Compare growing streams, the production-style size hint (+16 KiB), and a recyclable prototype. The prototype zeroes returned buffers and caps both its small and large free pools at 64 MiB each. Its package is a benchmark-only dependency; production buffering is unchanged.
- HTTPS: a generated localhost certificate, HTTP/1.1, a 1 KiB body and 150 requests per round. Compare a new handler/client per request against shared clients with infinite/two-minute connection lifetimes. The batch test runs 16 concurrent requests with an injected 10 ms server delay and 30 batches per round. Its latency/throughput are per **batch**, not per request.
- Connection rotation: a `ConnectCallback` simulates a resolver switching destination ports while keeping the hostname fixed. This validates connection-lifetime behavior, not AWS DNS timing. The certificate callback accepts only the generated fixture certificate and must not be copied into production.

The default-tiering run includes noticeable first-round JIT effects. The separate no-tiering run is a control, not a proposed production runtime setting. Neither run is an AWS Fargate benchmark. Run the application workload on its actual task configuration before using these figures for capacity planning.

See the [native migration guide](../docs/native-crypto-migration.md) and [the historical report](../docs/performance-profiling.md), [configuration](../docs/performance.md), and [raw results](results/).

The [complete native migration report](../docs/native-crypto-performance.md) compares the final .NET 8 implementation with the previous signing-only migration on the same runtime and container limits.
