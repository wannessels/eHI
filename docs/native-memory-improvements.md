# Native CMS memory reductions (.NET 8)

This historical snapshot predates full native streaming. See the [streaming implementation and measurements](native-streaming-performance.md) for current behavior.

Keeping payloads outside signature metadata substantially reduces native CMS memory use. `Settings.Default.UseNativeCrypto` remains the backend selector; the obsolete signing-only flag has been removed.

## Matched 8 MiB round-trip comparison

| Measurement | Before | After | Reduction |
|---|---:|---:|---:|
| Managed allocation per round trip | 296.29 MiB | 96.27 MiB | 68% |
| Process peak working set | 492.86 MiB | 307.54 MiB | 38% |
| Median round mean | 317.14 ms | 241.67 ms | 24% |

Before: production commit `b75a7b2`. After: `4c0d4ae`. Both run on .NET 8.0.31, Debian 12 x64, one CPU, 1 GiB container memory, workstation GC, default tiering, on the same local AMD Ryzen 7 PRO 4750U host. The stream threshold is 1 MiB. Each benchmark runs in a **fresh process**, with only the 8 MiB native scenario: five warm-ups followed by three rounds of twelve operations. Allocation and latency are medians of the round values; peak working set is the maximum over that process's measurements. Input generation and key creation are outside measured operations.

Unlike the earlier mixed-backend benchmark, these process peaks are not contaminated by previous scenarios. They still include runtime/JIT, warm-ups, retained buffers and GC behavior; they are not per-request live-memory measurements. These are local component results, not Fargate capacity estimates or concurrency measurements. Timing remains sensitive to host scheduling and throttling.

## Changes

- Sign detached CMS metadata, then attach the payload once. Certificate-chain and timestamp updates operate on metadata without repeatedly copying the message body.
- Write final signed envelopes directly to their destination stream. Native AES envelope construction also uses sized segments, avoiding the additional full-ciphertext ASN.1 writer buffer.
- Read primitive DER ciphertext directly from its containing message before native AES decryption. Constructed BER ciphertext from streaming senders still requires flattening.
- Detach content during native completion, preserving the original signature and payload while updating metadata. Release inner plaintext references before awaiting an outer timestamp.

The platform CMS implementation retains defensive content copies and encodes its structures during signing; using detached metadata removes payload copies from those operations. See the [platform implementation](https://github.com/dotnet/runtime/blob/v10.0.0/src/libraries/System.Security.Cryptography.Pkcs/src/System/Security/Cryptography/Pkcs/SignedCms.cs). The library still uses platform cryptographic primitives and keeps the same signature validation, timestamp and revocation policy.

## Remaining options

Native mode still buffers inputs, AES results and verification content. `InMemorySize` controls stream storage; it is not a hard cap on internal memory. Fully streaming native signing/verification would require a further CMS design change. BouncyCastle mode remains available for streaming large messages, with its exportable-key requirement and greater CPU cost. Its previous 8 MiB allocation measurement was about 49 MiB per round trip; it was not remeasured in this isolated native comparison.

Bound active requests through the shared `OperationPolicy`, and size concurrency from representative payloads and measured resident memory on the actual Fargate task. Lowering the stream threshold or introducing a large array pool alone will not eliminate native CMS buffers; retained pool capacity can also keep process memory high.

## Validation and reproduction

All 65 deterministic regression/interoperability tests pass on Windows and Linux .NET 8. Coverage includes cross-backend messages and completion, B/T/LT/LTA profiles, modified signatures/content, cancellation, legacy raw RSA-PSS, and ASN.1 length/AES padding boundaries with forced temporary-file output. The full solution builds on both platforms.

- [Before measurements](../benchmarks/results/native-memory-before-net8-1cpu-1g.json)
- [After measurements](../benchmarks/results/native-memory-after-net8-1cpu-1g.json)
- [Benchmark methodology](../benchmarks/README.md)

Run `./benchmarks/run-linux.ps1 -Suite native-memory`. The measured comparison used archives of the two commits in the same pinned SDK image and limits, sequentially. Only `benchmarks/Program.cs` and `benchmarks/CryptoProfiles.cs` from the after commit were copied into the before archive to add the identical isolated scenario; baseline production code was unchanged. Release signing was disabled because the private release signing key is not in the repository.
