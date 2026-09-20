# Selectable cryptography backends: .NET 8 measurements

`Settings.Default.UseNativeCrypto` selects native .NET (`true`, default) or streaming BouncyCastle (`false`). Both modes use the same current certificate, timestamp and revocation policy. See the [migration guide](native-crypto-migration.md#backend-selection) for scope, lifetime and private-key requirements.

The restored BouncyCastle backend reduces large-message allocation substantially, at a CPU/latency cost. These measurements cover production commit `a6c9f94`, Release, .NET 8.0.31, Debian 12 x64, workstation GC, one CPU and 1 GiB container memory on a local AMD Ryzen 7 PRO 4750U host. They are component measurements, not AWS Fargate capacity estimates.

## Default 1 MiB stream threshold

| Payload | Native round trip | BouncyCastle round trip | Native allocated/op | BouncyCastle allocated/op |
|---|---:|---:|---:|---:|
| 32 KiB | 6.83 ms | 32.11 ms | 1.32 MiB | 0.90 MiB |
| 1 MiB | 60.96 ms | 126.15 ms | 37.23 MiB | 9.68 MiB |
| 1 MiB + 1 B | 54.85 ms | 136.47 ms | 37.30 MiB | 6.81 MiB |
| 8 MiB | 325.88 ms | 727.41 ms | 296.29 MiB | 48.85 MiB |

At 8 MiB, streaming allocates about 84% less managed memory per round trip, while native finishes about 2.2 times faster. The allocation step just above 1 MiB comes from switching intermediate streams to temporary files. Raising the threshold to 64 MiB increased BouncyCastle's 8 MiB allocation to 96.58 MiB and reduced its measured time to 474.68 ms. Native still allocated 296.17 MiB with the higher threshold, because its CMS implementation buffers internally.

Allocated bytes are cumulative allocation per operation, **not peak live memory**. The process reached about 484 MiB peak working set, but native scenarios ran before BouncyCastle scenarios in the same process. That cumulative peak cannot establish a resident-memory comparison between backends. Size Fargate concurrency using representative concurrent requests and measured resident memory on the actual task configuration.

Each figure is the median of three round means after five warm-up operations. CPU throttling, JIT effects and host scheduling produced noticeable timing variation. Use these timings directionally; the allocation difference is the clearer result. The earlier [native migration comparison](native-crypto-performance.md) is a separate historical run and should not be used to infer a timing regression between these commits.

## Coverage and reproduction

The CMS benchmark uses B-level signatures, a cached RSA-2048 WebKey signer, an AES-128 shared recipient key and reused sealer/unsealer instances. It checks signature validity and decoded content. The raw data also includes RSA-2048/3072 signing measurements and the 64 MiB threshold cases. Certificate chains, remote TSA/STS calls and SOAP transport are excluded. HTTP pooling code is unchanged; its existing [profiling report](performance-profiling.md) remains applicable.

The solution builds on Windows and genuine Linux .NET 8. All 64 deterministic regression/interoperability tests pass on both, including both backends, cross-backend messages, AES key sizes, certificate and WebKey recipients, concurrent ECDSA, B/T/LT/LTA completion, legacy raw RSA-PSS, cancellation, and tampering in either signed layer. The selected 15 existing offline PKI tests also pass on Windows and Linux. NuGet.org reported no known vulnerable packages in the production dependency graph at validation time.

- [Raw measurements](../benchmarks/results/backends-net8-1cpu-1g.json)
- [Benchmark methodology and pinned SDK image](../benchmarks/README.md)

Run `./benchmarks/run-linux.ps1 -Suite crypto` to reproduce the two-backend comparison. This measurement used an archive of the exact committed sources in the same pinned image and limits. Release assembly signing was disabled because the private release signing key is not in the repository. Tests use generated credentials and local fixtures; no live eHealth endpoints or private production credentials were used.
