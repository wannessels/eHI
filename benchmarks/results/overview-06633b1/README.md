# Performance overview measurements

These fourteen JSON files are the full runs behind the [published performance overview](https://claude.ai/artifact/GWnKD6GXnnzyTeK7NXH2qr), measured on 20 September 2026. They are copied unchanged from the reviewed benchmark outputs.

- Production source: `06633b13b1035620c6b75e20de5942158523d230`.
- Benchmark-only changes: the `--trust system` option committed alongside these results. Production code was unchanged during measurement.
- Image: `mcr.microsoft.com/dotnet/sdk@sha256:78235e09001f52b6592c458ac010775ebac6725422e80cd0c1650590f67b2743`.
- Runtime: .NET 8.0.31, Debian 12, x64, workstation GC, default tiering.
- Docker CPU quota: 4 CPUs; memory limit: 16 GiB. The Docker Desktop VM reported 15,565,279,232 bytes of total memory, so the cgroup limit is not a claim that 16 GiB of physical memory was reserved.
- One Release build in one disposable container; each case ran sequentially in a fresh process, with five warm-ups and three measured rounds. No `--quick` runs are included.

The [portable batch script](../../run-overview-linux.ps1) preserves the measured cases, order, image and resource limits. Its path handling and failure reporting were made portable for the committed version. It benchmarks the current checkout and writes new outputs under `artifacts/profiling`; these recorded files are not overwritten.

Pharmacy profiles cover native/custom trust at four and eight workers, BouncyCastle/custom trust at four and eight workers, native/system trust at four and eight workers, and BouncyCastle/system trust at four workers. They use sixteen prescribers, 350,000 Citizen CA CRL entries, and 20,000 eHealth-platform CA CRL entries. System-trust runs install generated authorities in the disposable container only. No live service or host trust store is used.

The remaining profiles cover 32 KiB seal/unseal at four and eight workers, 8 MiB and 32 MiB at the default 16 MiB per-stream threshold, 32 MiB with a 64 MiB threshold, key primitives and SOAP signing. The small-message profiles exclude certificate validation, revocation and transport; the pharmacy profiles exclude STS, KGSS and SOAP transport. These are local Docker measurements, not a matched baseline against master or a deployment capacity guarantee.

Throughput and latency ranges in the overview are the minimum and maximum of the three rounds. Primitive and SOAP figures use the median round mean. Peak working set is the process peak, including fixture allocations; initial block-pool allocation remains visible in the first measured round.
