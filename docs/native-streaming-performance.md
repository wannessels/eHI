# Native CMS streaming on .NET 8

Native mode now streams signing, encryption, verification, decryption and completion. It remains selected by `Settings.Default.UseNativeCrypto = true`, the default. The BouncyCastle backend is still available with `false`. No additional streaming flag is required.

## Measured memory and latency

| Scenario | Managed allocation/round trip | Process peak working set | Median round mean |
|---|---:|---:|---:|
| Previous native, 8 MiB | 96.27 MiB | 305.68 MiB | 185.71 ms |
| Streaming native, 8 MiB | 0.48 MiB | 60.47 MiB | 534.77 ms |
| Streaming native, 32 MiB | 0.48 MiB | 89.45 MiB | 963.37 ms |

For 8 MiB, managed allocation dropped about 99.5% and peak working set about 80%. Increasing the payload to 32 MiB left managed allocation approximately unchanged. The benchmark creates a payload-sized input array outside the measured operation, which is included in process peak memory; the 32 MiB process therefore includes a larger caller-owned buffer.

This is a memory/latency trade-off: the 8 MiB streaming round trip was about 2.9 times slower in this local run. The staged implementation makes additional passes and uses temporary files. CPU time per operation was approximately 187 ms before, 280 ms for streaming 8 MiB and 962 ms for streaming 32 MiB. Scheduling, file I/O, cache state and JIT behavior affect wall-clock results. These measurements do not establish Fargate service capacity.

## Implementation and limits

Payload hashing is incremental. RSA-PSS/ECDSA signing and verification use platform hash-signature APIs; AES encryption/decryption uses native `CryptoStream` transforms. The framing layer accepts definite DER and constructed/indefinite BER content without flattening payloads. Platform `SignedCms` handles only signature metadata, with the existing certificate, timestamp and revocation policy.

Signed attributes bind the content type and computed message digest; signature and digest algorithms, RSA-PSS parameters and optional algorithm-protection attributes are checked. Legacy signatures without signed attributes also use incremental verification. The CMS rules are described in [RFC 5652 sections 5.4–5.6](https://www.rfc-editor.org/rfc/rfc5652.html#section-5.4). CMS countersignatures are rejected by the native eHealth profile; supported signature timestamps retain their existing validation path.

Each native stage spills to disk above `Settings.Default.InMemorySize` (1 MiB default). Known large stages start on disk immediately. Sealing non-seekable input first spools it for the signing and embedding passes. Unsealing/verification can read non-seekable inputs incrementally. Temporary files are deleted when their owning streams are disposed, including failed/cancelled operations. Callers own returned streams and must continue checking unseal validation/trust status.

Decoded metadata is capped by `Settings.Default.MaximumNativeMetadataSize` (16 MiB per CMS layer); BER nesting is limited to 32 levels. Payload size is not limited by a whole-message byte array. Memory still depends on metadata, certificate/revocation processing, caller buffers, the chosen stream threshold and active request count. Temporary-storage capacity and latency now matter more; keep admission limits appropriate to the task configuration. This is streaming through temporary stages, not a single-pass network pipeline.

## Validation

The complete solution builds on Windows and genuine Linux .NET 8. All 75 regression/interoperability tests pass on both platforms, and 15 selected offline PKI checks pass on Linux. Coverage includes:

- Native/BouncyCastle round trips, independent platform CMS verification, B/T/LT/LTA completion and certificate/WebKey recipients.
- RSA-PSS, legacy RSA-PKCS#1/SHA-512, concurrent ECDSA, AES key sizes and legacy raw signatures.
- A generated 32 MiB non-seekable payload, complete content hashing and an allocation bound at a 64 KiB spill threshold.
- Empty payloads, length/padding boundaries, nested BER chunks, excessive nesting, malformed/truncated lengths, metadata limits and trailing data.
- Modified content/signatures, incorrectly declared RSA-PSS parameters, cryptographically signed incorrect content types, and cancellation with caller-stream ownership preserved.

## Reproduction

Before: production commit `ba97cae`. After: `f3dd4e1`. Each scenario ran in a fresh process, sequentially in the same pinned .NET 8 SDK image, with one CPU and 1 GiB memory. Runtime: .NET 8.0.31, Debian 12 x64, workstation GC, default tiering, local AMD Ryzen 7 PRO 4750U host. Each case used five warm-ups and three rounds of twelve operations, B-level RSA-2048 WebKey signing and an AES-128 shared recipient key. Figures are medians of round means/allocations and the maximum process peak across rounds. No live eHealth endpoints were called.

Only the current benchmark `Program.cs` and `CryptoProfiles.cs` were copied into the before archive to run the identical scenario; baseline production code was unchanged. Release assembly signing was disabled because the private release key is not in the repository.

```powershell
./benchmarks/run-linux.ps1 -Suite native-memory
./benchmarks/run-linux.ps1 -Suite native-memory -PayloadMiB 32
```

- [Buffered native 8 MiB data](../benchmarks/results/native-streaming-before-8mib-net8-1cpu-1g.json)
- [Streaming native 8 MiB data](../benchmarks/results/native-streaming-after-8mib-net8-1cpu-1g.json)
- [Streaming native 32 MiB data](../benchmarks/results/native-streaming-after-32mib-net8-1cpu-1g.json)
- [Configuration and backend scope](native-crypto-migration.md)
