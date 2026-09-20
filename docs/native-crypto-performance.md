# Complete native migration: .NET 8 measurements

This historical snapshot measured the migration that removed BouncyCastle completely. A [selectable streaming backend](native-crypto-migration.md#backend-selection) has since been restored. The original migration was **not an unqualified performance win**: native CMS/AES was faster for larger messages, but the platform CMS API allocated more memory than the previous streaming implementation.

Measured on .NET 8.0.31, Debian 12, Linux x64, one CPU and 1 GiB container memory, workstation GC. Both implementations ran sequentially on the same local Docker host (AMD Ryzen 7 PRO 4750U), using the same pinned SDK image. These are component measurements, not AWS Fargate service-capacity results.

- Before: production commit `86084d6`, with native RSA-PSS enabled but CMS/encryption still using BouncyCastle.
- After: production commit `b6ab209`, using platform cryptography throughout.
- Each result is the median of three round means after five warm-up operations. Input, recipient type and test procedure match the [benchmark methodology](../benchmarks/README.md). Initial JIT effects and scheduling noise remain; the figures are directional, not service-level guarantees.

## CMS seal + unseal

| Payload | Signing-only migration | Fully native | Speed ratio | Allocation before | Allocation after |
|---|---:|---:|---:|---:|---:|
| 32 KiB | 5.52 ms | 5.67 ms | 0.97x | 0.79 MiB | 1.32 MiB |
| 1 MiB | 85.12 ms | 31.49 ms | 2.70x | 9.57 MiB | 37.23 MiB |
| 1 MiB + 1 B | 83.56 ms | 33.11 ms | 2.52x | 6.71 MiB | 37.30 MiB |
| 8 MiB | 549.13 ms | 230.04 ms | 2.39x | 48.74 MiB | 296.29 MiB |

The small-message result is effectively unchanged at this measurement precision. Large-message latency improved by about 2.4-2.7x, while allocation increased by about 4-6x. Allocated bytes are cumulative per operation, **not simultaneous resident memory**. The fully native process reached approximately 451 MiB peak working set by the end of the default-threshold scenarios; that peak is cumulative across earlier scenarios and must not be treated as a per-request measurement.

Raising the in-memory threshold to 64 MiB did not remove the internal copies: the 8 MiB native round trip still allocated about 296 MiB, with a median mean of 239 ms. The stream threshold controls output storage; it cannot make `SignedCms` stream its internal content.

For Fargate, retain bounded admission and select concurrency from actual resident-memory measurements. Large payloads may require fewer concurrent operations or a larger task memory allocation. Native algorithms reduce CPU work, but removing BouncyCastle's streaming CMS path shifts cost toward buffering and GC. A future bounded-memory CMS implementation would require a separate streaming encoding/verification design; it is not supplied by .NET's public `SignedCms` API.

## Scope and validation

The CMS case uses B-level signatures, an RSA-2048 WebKey signer and an AES-128 shared recipient key. It excludes SOAP transport, certificate-chain validation and remote eHealth calls. Signing-only microbenchmarks are retained in the raw results; BouncyCastle there is strictly a benchmark comparison dependency.

The migration passes 38 deterministic regression/interoperability tests and 15 existing offline PKI checks on Windows and Linux .NET 8. The production dependency audit contains no BouncyCastle package. The explicit NuGet.org vulnerability query returned no known vulnerable packages for the production service graph at the time of validation.

## Raw data and reproduction

- [Fully native .NET 8 results](../benchmarks/results/native-net8-1cpu-1g.json)
- [Signing-only baseline on .NET 8](../benchmarks/results/signing-only-net8-1cpu-1g.json)
- [Native migration/API guide](native-crypto-migration.md)

Run the current implementation with `./benchmarks/run-linux.ps1 -Suite crypto`. The image digest, CPU/memory limits and exact build arguments are in that script.

For the matched baseline, export commit `86084d6` into a separate directory. Change only the benchmark project's target to `net8.0`, add the benchmark-only `Microsoft.Bcl.Cryptography` package version `10.0.12` (for the TLS fixture loader), and restrict its CMS mode loop to `new[] { true }`. Production library sources remain unchanged. Build Release with `SignAssembly=false`, then run the crypto suite in the same pinned .NET 8 container with the same CPU/memory limits. These harness adaptations are the only baseline changes.
