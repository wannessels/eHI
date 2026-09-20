using System;
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>Library metrics published through System.Diagnostics.Metrics on the <see cref="MeterName"/> meter.</summary>
    /// <remarks>Nothing is exported by the library itself: subscribe with a MeterListener, OpenTelemetry (AddMeter) or dotnet-counters.</remarks>
    public static class EHealthMetrics
    {
        /// <summary>Name of the meter that carries every instrument below.</summary>
        public const string MeterName = "Egelke.EHealth";
        /// <summary>The meter itself, so other libraries in the family can add instruments under the same name.</summary>
        public static readonly Meter Meter = new Meter(MeterName, typeof(EHealthMetrics).Assembly.GetName().Version?.ToString());
        /// <summary>Completed top-level operations, tagged by operation and outcome (ok, error, cancelled).</summary>
        public static readonly Counter<long> Operations = Meter.CreateCounter<long>("ehealth.operations", "{operation}", "Completed top-level operations by operation and outcome");
        /// <summary>Top-level operation duration including admission wait, tagged like <see cref="Operations"/>.</summary>
        public static readonly Histogram<double> OperationDuration = Meter.CreateHistogram<double>("ehealth.operation.duration", "ms", "Top-level operation duration including admission wait");
        /// <summary>Time an operation waited for an admission slot.</summary>
        public static readonly Histogram<double> QueueDuration = Meter.CreateHistogram<double>("ehealth.operation.queue.duration", "ms", "Time an operation waited for an admission slot");
        /// <summary>Admitted operations in progress, tagged by operation.</summary>
        public static readonly UpDownCounter<long> ActiveOperations = Meter.CreateUpDownCounter<long>("ehealth.operations.active", "{operation}", "Admitted operations in progress");
        /// <summary>Certificate paths served, tagged by source (cache or platform).</summary>
        public static readonly Counter<long> ChainBuilds = Meter.CreateCounter<long>("ehealth.chain.builds", "{chain}", "Certificate paths served from the cache or built by the platform");
        /// <summary>Platform chain build duration.</summary>
        public static readonly Histogram<double> ChainBuildDuration = Meter.CreateHistogram<double>("ehealth.chain.build.duration", "ms", "Platform chain build duration");
        /// <summary>CRL and OCSP downloads, tagged by type and outcome.</summary>
        public static readonly Counter<long> RevocationDownloads = Meter.CreateCounter<long>("ehealth.revocation.downloads", "{download}", "CRL and OCSP downloads by type and outcome");
        /// <summary>CRL and OCSP download duration.</summary>
        public static readonly Histogram<double> RevocationDownloadDuration = Meter.CreateHistogram<double>("ehealth.revocation.download.duration", "ms", "CRL and OCSP download duration");
        /// <summary>Bytes of downloaded revocation evidence, tagged by type.</summary>
        public static readonly Counter<long> RevocationDownloadBytes = Meter.CreateCounter<long>("ehealth.revocation.download.bytes", "By", "Bytes of downloaded revocation evidence");
        /// <summary>SAML token requests, tagged by type (issue or renew) and outcome.</summary>
        public static readonly Counter<long> StsRequests = Meter.CreateCounter<long>("ehealth.sts.requests", "{request}", "SAML token requests by type and outcome");
        /// <summary>SAML token request duration.</summary>
        public static readonly Histogram<double> StsRequestDuration = Meter.CreateHistogram<double>("ehealth.sts.request.duration", "ms", "SAML token request duration");
        /// <summary>RFC 3161 timestamp requests, tagged by outcome.</summary>
        public static readonly Counter<long> TimestampRequests = Meter.CreateCounter<long>("ehealth.timestamp.requests", "{request}", "RFC 3161 timestamp requests by outcome");
        /// <summary>RFC 3161 timestamp request duration.</summary>
        public static readonly Histogram<double> TimestampRequestDuration = Meter.CreateHistogram<double>("ehealth.timestamp.request.duration", "ms", "RFC 3161 timestamp request duration");
        /// <summary>Payload spools created, tagged by storage (memory or file).</summary>
        public static readonly Counter<long> Spools = Meter.CreateCounter<long>("ehealth.spools", "{spool}", "Payload spools created by storage");
        /// <summary>Spools that outgrew the in-memory threshold and moved to a temporary file.</summary>
        public static readonly Counter<long> SpoolSpills = Meter.CreateCounter<long>("ehealth.spool.spills", "{spool}", "Spools moved from memory to a temporary file");
        /// <summary>Bytes written to spools, tagged by storage.</summary>
        public static readonly Counter<long> SpoolBytes = Meter.CreateCounter<long>("ehealth.spool.bytes", "By", "Bytes written to payload spools by storage");
        /// <summary>Time waiting for a private-key handle before signing.</summary>
        public static readonly Histogram<double> SigningQueueDuration = Meter.CreateHistogram<double>("ehealth.signing.queue.duration", "ms", "Time waiting for a signing-key handle");
        static EHealthMetrics()
        {
            Meter.CreateObservableGauge("ehealth.revocation.cache.entries", () => (long)RevocationCache.Count, "{entry}", "Retained revocation evidence entries");
            Meter.CreateObservableGauge("ehealth.revocation.cache.bytes", () => RevocationCache.EstimatedSizeBytes, "By", "Estimated memory retained by revocation evidence");
            Meter.CreateObservableGauge("ehealth.chain.cache.entries", () => (long)ChainCache.Count, "{entry}", "Retained certificate paths");
            Meter.CreateObservableGauge("ehealth.certificate.cache.entries", () => (long)CertificateCache.Count, "{entry}", "Retained decoded certificates");
            Meter.CreateObservableGauge("ehealth.key.cache.entries", () => (long)PublicKeyCache.Count, "{entry}", "Retained certificate public keys");
        }
        /// <summary>Outcome tag value for a failed operation.</summary>
        public static string Outcome(Exception error) => error is OperationCanceledException ? "cancelled" : "error";
        /// <summary>Counts one completion and records its duration since <paramref name="started"/> (a Stopwatch timestamp).</summary>
        public static void Record(Counter<long> count, Histogram<double> duration, long started, in TagList tags)
        {
            count.Add(1, tags); duration.Record(RuntimeCompat.GetElapsedTime(started).TotalMilliseconds, tags);
        }
    }
}
