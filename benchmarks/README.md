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

`-Suite keys` measures the per-object cost of certificate decoding versus handle copies and of the public-key construction paths on the platform crypto stack. The executable also accepts `--suite crypto|memory|http|native-memory|keys|all`, `--quick`, and `--output path`. Run `-Suite native-memory` in a fresh container/process for an isolated 8 MiB native CMS round trip, or add `-PayloadMiB 32` to check scaling. The executable equivalent is `--suite native-memory --payload-mib 32`. Use `-ThresholdMiB` (executable: `--threshold-mib`) to override the current 16 MiB default; explicitly select 1 MiB when comparing with older recorded profiles. Its process peak working set is not contaminated by earlier payload sizes or the BouncyCastle cases, but includes the benchmark's input byte array. It measures single-operation concurrency, not a concurrency sizing recommendation.

## Method

Each scenario performs five unmeasured warm-up operations, followed by three measurement rounds. GC is forced between rounds. Reported summaries use the median of the three round means, not a pooled request percentile. Each JSON row retains its own mean, p50/p95, allocations, CPU time and collection counts. Peak working set is cumulative for the process, not a per-case peak. Process-wide allocation measurements include both client and server for HTTP.

- Signing: 200 operations per round, RSA-2048/3072, 64 B/256 KiB input. Key generation/export and factory creation happen outside measurement. The platform case uses RSA.SignData with PSS; it includes hashing plus signing. Generated signatures are checked before measurement.
- CMS: production B-level seal/unseal with a reused RSA-2048 WebKey signer and AES-128 shared recipient key. Payloads are 32 KiB, 1 MiB, 1 MiB + 1 B and 8 MiB. Each round uses 40 operations through 1 MiB and 12 above it. Signature validity, decoded length and the final payload byte are checked. No certificate revocation, STS/TSA calls or SOAP transport are part of this case. CMS scenarios measure both selectable production backends using pinned factories; older committed results retain the former partial-migration variants. The alternative memory threshold is 64 MiB versus the current 16 MiB default (older committed profiles used a 1 MiB default).
- Streams: three temporary streams, three copies and a final `ToArray`, with 150 iterations through 1 MiB and 40 at 8 MiB. Compare growing streams, the production-style size hint (+16 KiB), and a recyclable prototype. The prototype zeroes returned buffers and caps both its small and large free pools at 64 MiB each. Its package is a benchmark-only dependency; production buffering is unchanged.
- HTTPS: a generated localhost certificate, HTTP/1.1, a 1 KiB body and 150 requests per round. Compare a new handler/client per request against shared clients with infinite/two-minute connection lifetimes. The batch test runs 16 concurrent requests with an injected 10 ms server delay and 30 batches per round. Its latency/throughput are per **batch**, not per request.
- Connection rotation: a `ConnectCallback` simulates a resolver switching destination ports while keeping the hostname fixed. This validates connection-lifetime behavior, not AWS DNS timing. The certificate callback accepts only the generated fixture certificate and must not be copied into production.

The default-tiering run includes noticeable first-round JIT effects. The separate no-tiering run is a control, not a proposed production runtime setting. Neither run is an AWS Fargate benchmark. Run the application workload on its actual task configuration before using these figures for capacity planning.

See the [native migration guide](../docs/native-crypto-migration.md) and [the historical report](../docs/performance-profiling.md), [configuration](../docs/performance.md), and [raw results](results/).

The [complete native migration report](../docs/native-crypto-performance.md) compares the final .NET 8 implementation with the previous signing-only migration on the same runtime and container limits.

The [selectable backend report](../docs/backend-crypto-performance.md) compares the current native and BouncyCastle streaming modes on .NET 8. Scratch results now use the `backends-net8-1cpu-1g` filename prefix.

The [native memory improvement report](../docs/native-memory-improvements.md) compares the optimized native implementation with its immediate predecessor in fresh processes. Use `-Suite native-memory` to reproduce that isolated scenario.

The [native streaming report](../docs/native-streaming-performance.md) measures the current implementation at 8 MiB and 32 MiB and compares it with the prior buffered native backend. It includes the observed memory/latency trade-off.

## Concurrent crypto

```powershell
./benchmarks/run-linux.ps1 -Suite crypto-concurrency -CpuLimit 2 -PayloadKiB 8192 -Concurrency 4 -Requests 32
./benchmarks/run-linux.ps1 -Suite crypto-concurrency -CpuLimit 2 -PayloadKiB 32 -Concurrency 8 -Requests 256
./benchmarks/run-linux.ps1 -Suite crypto-concurrency -CpuLimit 4 -MemoryGiB 16 -PayloadKiB 8192 -Concurrency 8 -ThresholdMiB 16
```

The executable accepts `--suite crypto-concurrency --payload-kib 8192 --concurrency 4 --requests 32 --threshold-mib 1`. Each scenario should run in a fresh process. Closed-loop workers share a sealer, unsealer, RSA-2048 key and immutable input, matching client context reuse. One shared admission policy bounds the complete seal/unseal request. Five warm-up requests precede three measured rounds. Workers wait on a start barrier; request latency includes dispatch, admission and both crypto operations, and throughput is completed requests per second. Per-request mean/p50/p95, peak active requests, allocations, CPU and process peak memory appear under `concurrencyDetails`. This measures steady concurrency, not an external arrival-rate/overload queue or live SOAP service. `-ThresholdMiB` varies the per-stream memory allowance, and `-CpuLimit`/`-MemoryGiB` set the container limits.

Add `-ServerGC` to compare Server GC; the raw metadata records the actual runtime mode. See the [4-vCPU/16-GiB report](../docs/fargate-latency-tuning.md) for all 24 before/after and tuning profiles.

## Pharmacy prescription retrieval

```powershell
./benchmarks/run-linux.ps1 -Suite pharmacy -CpuLimit 4 -MemoryGiB 4 -Concurrency 4 -Requests 64
./benchmarks/run-linux.ps1 -Suite pharmacy -CpuLimit 4 -MemoryGiB 4 -Concurrency 4 -Requests 64 -CitizenCrlEntries 0
```

The executable accepts `--suite pharmacy --concurrency 4 --requests 64 --prescribers 16 --citizen-crl-entries 350000 --ehealth-crl-entries 20000 --backend native`; `--backend bouncycastle` (`-Backend bouncycastle` for the script) runs the same scenario on the BouncyCastle streaming backend. Each closed-loop request does what a pharmacy does for one prescription: seal a 1 KiB request to the Recip-e encryption certificate with the pharmacy certificate, unseal the Recip-e response (signed by the Recip-e certificate, encrypted to the pharmacy certificate), and unseal the 4 KiB prescription inside it with its KGSS secret key at LT level, with a time-mark provider standing in for Recip-e. Sixteen prescriber certificates rotate across requests. STS, KGSS and SOAP transport are outside the scenario; the KGSS key exchange has the same shape as the request/response pair.

Certificates are generated in-process with the shapes of the Belgian hierarchies: pharmacy, Recip-e and encryption certificates chain root > government CA > eHealth-platform CA; prescriber certificates chain root > Citizen CA, like eID signature certificates. An in-process HTTP server serves every CRL and there is no OCSP responder, so each chain validation falls back to CRLs. The Citizen CA list defaults to 350,000 entries, matching the live `eidc201204.crl` (12,263,364 bytes, committed unchanged as `pki-test/files/eid79021802145.crl`). The eHealth-platform CA list defaults to 20,000 entries; that is an assumption, because the live Zetes list was unavailable when this scenario was written. Root and government lists are small.

The result records the cold first request (CRL downloads, parsing and signature checks), the parse time of the generated and committed Citizen CA lists, and per round the cumulative CRL download count plus the revocation cache's entry count and estimated bytes. A download count that keeps growing across rounds means a list is not being retained.
