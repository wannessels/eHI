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
        private static readonly Meter meter = new Meter(MeterName, typeof(EHealthMetrics).Assembly.GetName().Version?.ToString());
        /// <summary>Completed top-level operations, tagged by operation and outcome (ok, error, cancelled).</summary>
        public static readonly Counter<long> Operations = meter.CreateCounter<long>("ehealth.operations", "{operation}", "Completed top-level operations by operation and outcome");
        /// <summary>Top-level operation duration including admission wait, tagged like <see cref="Operations"/>.</summary>
        public static readonly Histogram<double> OperationDuration = meter.CreateHistogram<double>("ehealth.operation.duration", "ms", "Top-level operation duration including admission wait");
        /// <summary>Time an operation waited for an admission slot.</summary>
        public static readonly Histogram<double> QueueDuration = meter.CreateHistogram<double>("ehealth.operation.queue.duration", "ms", "Time an operation waited for an admission slot");
        /// <summary>Admitted operations in progress, tagged by operation.</summary>
        public static readonly UpDownCounter<long> ActiveOperations = meter.CreateUpDownCounter<long>("ehealth.operations.active", "{operation}", "Admitted operations in progress");
        /// <summary>Certificate paths served, tagged by source (cache or platform).</summary>
        public static readonly Counter<long> ChainBuilds = meter.CreateCounter<long>("ehealth.chain.builds", "{chain}", "Certificate paths served from the cache or built by the platform");
        /// <summary>Platform chain build duration.</summary>
        public static readonly Histogram<double> ChainBuildDuration = meter.CreateHistogram<double>("ehealth.chain.build.duration", "ms", "Platform chain build duration");
        /// <summary>CRL and OCSP downloads, tagged by type and outcome.</summary>
        public static readonly Counter<long> RevocationDownloads = meter.CreateCounter<long>("ehealth.revocation.downloads", "{download}", "CRL and OCSP downloads by type and outcome");
        /// <summary>CRL and OCSP download duration.</summary>
        public static readonly Histogram<double> RevocationDownloadDuration = meter.CreateHistogram<double>("ehealth.revocation.download.duration", "ms", "CRL and OCSP download duration");
        /// <summary>Bytes of downloaded revocation evidence, tagged by type.</summary>
        public static readonly Counter<long> RevocationDownloadBytes = meter.CreateCounter<long>("ehealth.revocation.download.bytes", "By", "Bytes of downloaded revocation evidence");
        /// <summary>SAML token requests, tagged by type (issue or renew) and outcome.</summary>
        public static readonly Counter<long> StsRequests = meter.CreateCounter<long>("ehealth.sts.requests", "{request}", "SAML token requests by type and outcome");
        /// <summary>SAML token request duration.</summary>
        public static readonly Histogram<double> StsRequestDuration = meter.CreateHistogram<double>("ehealth.sts.request.duration", "ms", "SAML token request duration");
        /// <summary>RFC 3161 timestamp requests, tagged by outcome.</summary>
        public static readonly Counter<long> TimestampRequests = meter.CreateCounter<long>("ehealth.timestamp.requests", "{request}", "RFC 3161 timestamp requests by outcome");
        /// <summary>RFC 3161 timestamp request duration.</summary>
        public static readonly Histogram<double> TimestampRequestDuration = meter.CreateHistogram<double>("ehealth.timestamp.request.duration", "ms", "RFC 3161 timestamp request duration");
        static EHealthMetrics()
        {
            meter.CreateObservableGauge("ehealth.revocation.cache.entries", () => (long)RevocationCache.Count, "{entry}", "Retained revocation evidence entries");
            meter.CreateObservableGauge("ehealth.revocation.cache.bytes", () => RevocationCache.EstimatedSizeBytes, "By", "Estimated memory retained by revocation evidence");
            meter.CreateObservableGauge("ehealth.chain.cache.entries", () => (long)ChainCache.Count, "{entry}", "Retained certificate paths");
        }
        /// <summary>Outcome tag value for a failed operation.</summary>
        public static string Outcome(Exception error) => error is OperationCanceledException ? "cancelled" : "error";
        /// <summary>Counts one completion and records its duration since <paramref name="started"/> (a Stopwatch timestamp).</summary>
        public static void Record(Counter<long> count, Histogram<double> duration, long started, in TagList tags)
        {
            count.Add(1, tags); duration.Record(Stopwatch.GetElapsedTime(started).TotalMilliseconds, tags);
        }
    }
}
