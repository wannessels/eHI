using System.Diagnostics;
using System.Text.Json;

internal sealed record ClosedLoopRound(int Round, int Concurrency, int PeakActiveRequests, int Requests, double MeanMs, double P50Ms, double P95Ms,
    double RequestsPerSecond, double AllocatedBytesPerRequest, double CpuMsPerRequest, int Gen2, long ProcessPeakWorkingSet, object? Details);

internal static class ClosedLoop
{
    internal static async Task<List<ClosedLoopRound>> RunAsync(int concurrency, int requests, Func<Task> request, Func<object?>? details = null)
    {
        if (concurrency < 1 || requests < concurrency) throw new ArgumentOutOfRangeException(nameof(requests));
        var rounds = new List<ClosedLoopRound>();
        for (int i = 0; i < 5; i++) await request();
        for (int round = 1; round <= Program.Rounds; round++)
        {
            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            using var process = Process.GetCurrentProcess();
            long allocated = GC.GetTotalAllocatedBytes(true); var cpu = process.TotalProcessorTime;
            int gen2 = GC.CollectionCount(2), next = -1, remainingWorkers = concurrency, active = 0, peakActive = 0;
            var latencies = new double[requests]; var workers = new Task[concurrency];
            var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            for (int worker = 0; worker < concurrency; worker++)
                workers[worker] = Task.Run(async () =>
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
                        try { await request(); }
                        finally { Interlocked.Decrement(ref active); }
                        latencies[index] = Stopwatch.GetElapsedTime(began).TotalMilliseconds;
                    }
                });
            await ready.Task;
            var elapsed = Stopwatch.StartNew(); start.SetResult(); await Task.WhenAll(workers); elapsed.Stop();
            process.Refresh(); Array.Sort(latencies);
            var result = new ClosedLoopRound(round, concurrency, peakActive, requests,
                latencies.Average(), latencies[requests / 2], latencies[Math.Min(requests - 1, (int)Math.Ceiling(requests * .95) - 1)],
                requests / elapsed.Elapsed.TotalSeconds, (GC.GetTotalAllocatedBytes(true) - allocated) / (double)requests,
                (process.TotalProcessorTime - cpu).TotalMilliseconds / requests, GC.CollectionCount(2) - gen2, process.PeakWorkingSet64, details?.Invoke());
            rounds.Add(result); Console.WriteLine(JsonSerializer.Serialize(result));
        }
        return rounds;
    }
}
