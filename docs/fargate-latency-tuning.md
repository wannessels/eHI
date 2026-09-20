# Latency and concurrency tuning for 4 vCPU / 16 GiB

Native sealing now processes the input once, piping the inner signed message directly through AES encryption and outer signing. This removes the inner/encrypted temporary files and supports async-only, non-seekable input without replay. Outer-signature retries reuse the digest. Unsealing feeds decrypted bytes directly into inner verification/output, removing another temporary stage while preserving certificate selection using the validated outer signing time. Payload copies and native temporary-file I/O are asynchronous. Memory streams reserve known sizes plus modest CMS overhead to avoid repeated growth copies.

For the tested 32 KiB/8 MiB workload, start with **four active crypto-heavy operations** and a **16 MiB per-stream threshold** on the requested 4-vCPU/16-GiB task. Larger messages still spill to temporary files. The library's portable defaults remain unchanged; apply the settings at application startup, before creating contexts:

```csharp
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Configuration;

Settings.Default.UseNativeCrypto = true;
Settings.Default.InMemorySize = 16L * 1024 * 1024;

// Register/reuse ONE instance for clients sharing the same capacity budget.
var policy = new OperationPolicy(4, TimeSpan.FromMinutes(1));
mda.OperationPolicy = policy;
kgss.OperationPolicy = policy;
```

Standalone crypto workflows can use the same policy's `RunAsync` around the complete workflow. Creating a policy per request does not provide a shared limit. The one-minute timeout above preserves the library default; set it to the application's deadline if different.

The measurements cover crypto, not the entire remote service call. A workload dominated by HTTP/STS/TSA waits may benefit from more end-to-end operations. Size that limit using actual service latency and arrival rate; these closed-loop results do not measure an overloaded incoming-request queue.

## 8 MiB requests, workstation GC

| Implementation | Concurrent requests | Stream threshold | Mean latency | p95 latency | Round trips/s | Process peak |
|---|---:|---:|---:|---:|---:|---:|
| Before | 4 | 1 MiB | 244.74 ms | 272.67 ms | 16.14 | 76.50 MiB |
| Optimized | 4 | 1 MiB | 165.80 ms | 227.97 ms | 23.89 | 79.50 MiB |
| Optimized, tuned | 4 | 16 MiB | 77.09 ms | 99.11 ms | 51.45 | 562.67 MiB |
| Optimized, tuned | 8 | 16 MiB | 163.76 ms | 240.10 ms | 45.50 | 564.53 MiB |
| Optimized, tuned | 16 | 16 MiB | 265.17 ms | 373.66 ms | 47.45 | 517.57 MiB |

At the unchanged threshold/concurrency, the code change reduced mean latency by about 32% and increased throughput about 48%. The larger threshold then traded available memory for fewer file operations: the tuned case was about 3.2 times faster than the original four-request case. Four active requests gave the best measured latency/throughput balance. More parallelism did not improve throughput in these runs.

The tuned threshold allocates about 24.18 MiB per request, compared with about 0.91 MiB for the optimized 1 MiB threshold. This is cumulative managed allocation, not simultaneously live memory. Measured process peak stayed below 565 MiB in the tuned workstation-GC cases. The threshold applies to each stream, not to the entire process; caller buffers, metadata, other workloads and queued requests need their own capacity budget.

## Small requests and Server GC

At 32 KiB and four concurrent requests, performance was approximately unchanged: mean latency 10.33 → 10.77 ms, p95 13.32 → 13.89 ms, throughput 387 → 370 requests/s. Allocation fell from about 0.55 to 0.25 MiB per request. Eight concurrent optimized requests produced almost the same throughput (371/s) but roughly doubled p95 to 26.80 ms. Small-message crypto/provider overhead remains significant; the change is not a universal speedup.

Separate Server-GC runs confirmed the concurrency/threshold recommendation:

| Implementation | Concurrent requests | Threshold | Mean | p95 | Round trips/s | Process peak |
|---|---:|---:|---:|---:|---:|---:|
| Before | 4 | 1 MiB | 338.35 ms | 418.86 ms | 11.73 | 84.80 MiB |
| Optimized | 4 | 1 MiB | 285.09 ms | 379.99 ms | 13.72 | 96.80 MiB |
| Optimized, tuned | 4 | 16 MiB | 95.99 ms | 125.66 ms | 41.21 | 366.40 MiB |
| Optimized, tuned | 8 | 16 MiB | 175.04 ms | 244.85 ms | 41.60 | 378.30 MiB |
| Optimized, tuned | 16 | 16 MiB | 339.41 ms | 521.46 ms | 36.13 | 417.40 MiB |

Do not switch the application's GC mode solely on these separate runs; wall-clock timing varied across runs. The raw metadata records the actual mode. The Server-GC runs used `DOTNET_gcServer=1`; GC configuration is read at process startup. See [Microsoft's GC configuration reference](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/garbage-collector#workstation-vs-server).

## Method and validation

Before: production commit `fc1fb4d`. After: `0805eeb`. A current benchmark-only `Program.cs` and `ConcurrentCryptoProfiles.cs` were copied into the baseline archive; baseline production code was unchanged. Each case ran in a fresh process in the pinned .NET 8 SDK container, with **4 CPUs and a 16 GiB cgroup limit**, on a local AMD Ryzen 7 PRO 4750U host. Runtime: .NET 8.0.31, Debian 12 x64, default tiering. The Docker VM reports about 14.5 GiB physical memory; measured process peaks were far below that. These are local component results, not a live Fargate service load test.

Closed-loop workers share a sealer, unsealer, RSA-2048 WebKey signer and immutable input; recipients use AES-128 key wrapping. Each logical request includes sealing, unsealing, validation and output disposal. Latency includes dispatch/admission wait. Workers start behind a barrier and yield at dispatch so small synchronously completing operations do not monopolize a worker. The recorded peak active request count reached each requested concurrency in every measured round.

Five warm-up requests precede three measured rounds, with forced GC between rounds. Each round uses 256 requests at 32 KiB or 32 requests at 8 MiB. Tables report medians of round means, p95 values and throughput; these are not pooled percentiles or service-level guarantees. Peak memory is the maximum recorded for each process, including the caller input array. The main sweep covers 1/4/8/16 concurrent requests, before/after at a 1 MiB threshold, followed by optimized 16 MiB threshold cases at 4/8/16 concurrency. Five additional cases use Server GC. Raw data includes all cases, including results where throughput did not improve.

All **77 deterministic regression/interoperability tests pass on Windows and Linux .NET 8**, and the full solution builds on both. New tests exercise eight shared-context async-only inputs, independent cancellation, and a transient outer-signature failure without replaying the source. Existing tests cover cross-backend CMS, B/T/LT/LTA profiles, RSA/ECDSA, recipient types, tampering, malformed BER, bounded allocation and cancellation. No live eHealth credentials or endpoints were used.

## Reproduce

```powershell
./benchmarks/run-linux.ps1 -Suite crypto-concurrency -CpuLimit 4 -MemoryGiB 16 -PayloadKiB 8192 -Concurrency 4 -Requests 32 -ThresholdMiB 1
./benchmarks/run-linux.ps1 -Suite crypto-concurrency -CpuLimit 4 -MemoryGiB 16 -PayloadKiB 8192 -Concurrency 4 -Requests 32 -ThresholdMiB 16
./benchmarks/run-linux.ps1 -Suite crypto-concurrency -CpuLimit 4 -MemoryGiB 16 -PayloadKiB 8192 -Concurrency 4 -Requests 32 -ThresholdMiB 16 -ServerGC
```

- [All 24 raw profiles](../benchmarks/results/latency-4cpu16g/)
- [Original four-request 8 MiB profile](../benchmarks/results/latency-4cpu16g/crypto-before-8192kib-c4-t1-4cpu16g.json)
- [Optimized default-threshold profile](../benchmarks/results/latency-4cpu16g/crypto-after-8192kib-c4-t1-4cpu16g.json)
- [Tuned four-request profile](../benchmarks/results/latency-4cpu16g/crypto-after-8192kib-c4-t16-4cpu16g.json)
- [Tuned Server-GC profile](../benchmarks/results/latency-4cpu16g/crypto-after-8192kib-c4-t16-4cpu16g-server.json)
