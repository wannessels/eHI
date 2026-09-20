using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging.Abstractions;

internal static class ConcurrentCryptoProfiles
{
    internal static async Task<object> RunAsync(int bytes, int concurrency, int requests, int thresholdMiB)
    {
        if (bytes < 1 || concurrency < 1 || requests < concurrency || thresholdMiB < 0) throw new ArgumentOutOfRangeException();
        Settings.Default.InMemorySize = checked((long)thresholdMiB * 1024 * 1024);
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa);
        var recipient = new SecretKey(new byte[] { 1 }, RandomNumberGenerator.GetBytes(16));
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, true).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, true).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection());
        var payload = RandomNumberGenerator.GetBytes(bytes);
        var policy = new OperationPolicy(concurrency, TimeSpan.FromMinutes(2));
        async Task Request() => await policy.RunAsync(async _ =>
        {
            using var input = new MemoryStream(payload, false);
            using var sealedData = await sealer.SealAsync(input, recipient, Array.Empty<EncryptionToken>());
            var result = await receiver.UnsealAsync(sealedData, sender, recipient);
            using (result.UnsealedData)
            {
                if (result.SecurityInformation.ValidationStatus != ValidationStatus.Valid || result.UnsealedData.Length != bytes) throw new Exception("Round trip validation failed");
                result.UnsealedData.Position = bytes - 1;
                if (result.UnsealedData.ReadByte() != payload[bytes - 1]) throw new Exception("Content mismatch");
            }
            return 0;
        });
        var rounds = new List<object>();
        try
        {
            for (int i = 0; i < 5; i++) await Request();
            for (int round = 1; round <= Program.Rounds; round++)
            {
                GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
                using var process = Process.GetCurrentProcess();
                long allocated = GC.GetTotalAllocatedBytes(true); var cpu = process.TotalProcessorTime;
                int gen2 = GC.CollectionCount(2), next = -1, remainingWorkers = concurrency, active = 0, peakActive = 0;
                var latencies = new double[requests]; var sealings = new Task[concurrency];
                var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                for (int worker = 0; worker < concurrency; worker++)
                    sealings[worker] = Task.Run(async () =>
                    {
                        if (Interlocked.Decrement(ref remainingWorkers) == 0) ready.SetResult();
                        await start.Task;
                        int index;
                        while ((index = Interlocked.Increment(ref next)) < requests)
                        {
                            long began = Stopwatch.GetTimestamp();
                            int current = Interlocked.Increment(ref active), previous;
                            do { previous = Volatile.Read(ref peakActive); } while (current > previous && Interlocked.CompareExchange(ref peakActive, current, previous) != previous);
                            // Dispatch all closed-loop requests fairly even when a small
                            // message completes synchronously. Include dispatch wait in latency.
                            await Task.Yield();
                            try { await Request(); }
                            finally { Interlocked.Decrement(ref active); }
                            latencies[index] = Stopwatch.GetElapsedTime(began).TotalMilliseconds;
                        }
                    });
                await ready.Task;
                var elapsed = Stopwatch.StartNew(); start.SetResult(); await Task.WhenAll(sealings); elapsed.Stop();
                process.Refresh(); Array.Sort(latencies);
                var result = new
                {
                    Round = round, PayloadBytes = bytes, Concurrency = concurrency, PeakActiveRequests = peakActive, Requests = requests, ThresholdMiB = thresholdMiB,
                    MeanMs = latencies.Average(), P50Ms = latencies[requests / 2], P95Ms = latencies[Math.Min(requests - 1, (int)Math.Ceiling(requests * .95) - 1)],
                    RequestsPerSecond = requests / elapsed.Elapsed.TotalSeconds,
                    AllocatedBytesPerRequest = (GC.GetTotalAllocatedBytes(true) - allocated) / (double)requests,
                    CpuMsPerRequest = (process.TotalProcessorTime - cpu).TotalMilliseconds / requests,
                    Gen2 = GC.CollectionCount(2) - gen2, ProcessPeakWorkingSet = process.PeakWorkingSet64
                };
                rounds.Add(result); Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(result));
            }
            return new { Method = "Closed-loop workers; per-request latency includes dispatch, shared admission and seal+unseal. Immutable input is shared. Fresh process per scenario; no external services.", Rounds = rounds };
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
    }
}
