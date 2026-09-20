# Performance profiling results

> Historical snapshot: these measurements predate the complete .NET 8 native-cryptography migration. See [the migration guide](native-crypto-migration.md); the old feature flag no longer selects a backend.

Measured on 2026-09-19 UTC (2026-09-20 Brussels), production source commit `f10ac4c`, in a local Docker Linux container limited to **1 CPU and 1 GiB RAM**. Runtime: .NET 10.0.12, Ubuntu 24.04.5, x64, workstation GC; host CPU: AMD Ryzen 7 PRO 4750U. This is a controlled local profile, **not an AWS Fargate capacity measurement**.

[Reproduction and methodology](../benchmarks/README.md) · [Default-runtime results](../benchmarks/results/linux-1cpu-1g.json) · [JIT-tiering-disabled control](../benchmarks/results/linux-1cpu-1g-no-tiering.json)

Tables show the median of three round means. Allocation figures are per operation. Default runtime settings are the primary results; the control checks whether the conclusions depend on JIT warm-up. Five warm-up operations did not eliminate all tiering effects: for example, the first RSA-2048 managed round averaged 13.07 ms, versus 7.04 and 6.10 ms in later rounds. Treat small timing differences as noise.

## Native RSA-PSS

| Scenario | BouncyCastle | Native | Ratio |
|---|---:|---:|---:|
| RSA-2048, 64 B | 7.04 ms | 0.64 ms | 11.0x |
| RSA-2048, 256 KiB | 8.07 ms | 0.74 ms | 10.8x |
| RSA-3072, 64 B | 18.32 ms | 1.88 ms | 9.8x |
| RSA-3072, 256 KiB | 19.84 ms | 2.03 ms | 9.8x |

The no-tiering control also favored native signing by approximately 9-11x. RSA-2048 signing allocations fell from approximately 32.4 KB to 1.1 KB per signature. The native implementation preserves SHA-256, MGF1/SHA-256, a 32-byte salt and trailer field 1. Tests cross-verify native/BouncyCastle signatures at 2048 and 3072 bits and validate detached CMS certificate signatures plus complete CMS round trips in both modes.

This historical measurement used the former signing-only feature flag, which has since been removed. Current code selects the complete message backend with `Settings.Default.UseNativeCrypto`; see [configuration](performance.md#native-cryptography).

Faster signing does not translate directly into the same application speedup:

| Complete CMS seal + unseal | Managed signing | Native signing | Improvement |
|---|---:|---:|---:|
| 32 KiB | 16.21 ms | 3.75 ms | 4.3x |
| 1 MiB | 89.14 ms | 64.74 ms | 1.4x |
| 1 MiB + 1 B | 81.46 ms | 77.55 ms | 1.05x |
| 8 MiB | 552.43 ms | 527.17 ms | 1.05x |

The control measured 3.2x for 32 KiB and only 1.01x at 8 MiB. These component profiles exclude remote calls, certificate validation and SOAP. Native signing is useful for small-message CPU throughput; large-message cost is dominated by other processing and buffering.

## Memory and temporary files

A bounded, zeroing recyclable-stream prototype reduced allocation by about **75% relative to the current size-hinted strategy**, including the unavoidable final byte-array copy:

| Three-buffer pipeline | Size hint: time / allocation | Recyclable prototype: time / allocation |
|---|---:|---:|
| 32 KiB | 0.06 ms / 176 KiB | 0.02 ms / 33 KiB |
| 1 MiB | 3.96 ms / 4.05 MiB | 1.89 ms / 1.00 MiB |
| 8 MiB | 20.89 ms / 32.05 MiB | 12.76 ms / 8.02 MiB |

This is a **stream component experiment**, not an integrated pooled-CMS result. Production still uses the existing stream factories. It is the strongest next memory optimization to implement and validate with actual concurrency; retained pool memory must be budgeted separately from allocation rate. Small-message results also show that always reserving input length + 16 KiB can over-allocate compared with ordinary growth.

Raising the in-memory threshold alone trades memory for latency. At 8 MiB, the native CMS round trip changed from **527 ms and 48.7 MiB allocated** to **403 ms and 96.5 MiB allocated** when the threshold rose from 1 MiB to 64 MiB. Gen-2 collections increased from 6 to 23 per 12-operation round. The control confirmed the tradeoff (764 to 628 ms, approximately doubled allocation).

Keep the existing threshold until the application's concurrent working set is measured. In a 1 GiB task, doubling per-operation allocation and increasing full collections may outweigh the isolated latency improvement. Test payloads just above the threshold as well: sealing compares cleartext length, whereas unsealing compares the larger sealed-message length.

## HTTP pooling

| Sequential localhost HTTPS | Median mean latency | Allocation | Connections across warm-up + 450 requests |
|---|---:|---:|---:|
| New client/handler per request | 4.18 ms | 39.0 KB | 455 |
| Shared, infinite lifetime | 0.31 ms | 4.5 KB | 1 |
| Shared, two-minute lifetime | 0.42 ms | 4.5 KB | 1 |

The branch already uses shared clients for OCSP/CRL/TSA, so the fresh-client comparison is a baseline, **not an additional speedup supplied by this work**. In the no-tiering control the two shared variants both averaged about 0.38 ms. A finite lifetime is a DNS-refresh/lifecycle improvement; these measurements show no reliable steady-state throughput advantage from changing the lifetime alone. Microsoft recommends a finite `PooledConnectionLifetime` for long-lived clients: [HttpClient guidance](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/http/httpclient-guidelines).

The simulated resolver switch retained server A with an infinite lifetime; a 100 ms lifetime reconnected to server B after expiration (one versus two connections). This uses a deliberately short test lifetime, not a production recommendation.

Connection limits affect queueing: for 16 concurrent requests with a 10 ms simulated remote delay, a limit of four connections took **48.35 ms per batch**, versus **14.36 ms** with a limit of 32 (16 connections actually used). The control was similar. Align any per-host connection cap with application admission limits and upstream capacity; arbitrarily low limits create another queue.

## Validation and deployment interpretation

- All 26 new regression tests passed on Windows and Linux. Linux tests ran on .NET 10 through runtime roll-forward; Windows tests ran on .NET 8.
- The 15 selected existing offline PKI tests passed on .NET 6. No live eHealth tests or root-certificate installations were used.
- Existing dependency-vulnerability and legacy API/documentation warnings remain in the repository's build output; this performance work does not upgrade those dependencies.
- All advertised service/library target frameworks build successfully. The six requested improvements have separate commits, followed by the native RSA-PSS feature flag, a final cancellation-scope correction, and this profiling harness/report.

Before sizing Fargate tasks, repeat with the real service mix, certificate identities, payload distribution, warm/cold caches, revocation failures and concurrency. Record p95/p99 latency, throughput, RSS, allocation/GC pressure, thread-pool queueing and external request counts. Keep native RSA-PSS opt-in until the chosen Linux image and production key provider pass interoperability testing. The pooling prototype and connection-lifetime experiments remain isolated to the benchmark project.
