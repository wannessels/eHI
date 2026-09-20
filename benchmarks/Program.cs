using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

internal static class Program
{
    internal static readonly List<Measurement> Results = new();
    internal static int Rounds = 3;
    internal static bool Quick;
    private static async Task Main(string[] args)
    {
        Quick = args.Contains("--quick");
        if (Quick) Rounds = 1;
        string Option(string name, string fallback) { int index = Array.IndexOf(args, name); return index < 0 ? fallback : args[index + 1]; }
        int Number(string name, int fallback) => int.Parse(Option(name, fallback.ToString()));
        string suite = Option("--suite", "all");
        string output = Option("--output", "profile.json");
        var metadata = new
        {
            StartedUtc = DateTime.UtcNow,
            SourceCommit = Environment.GetEnvironmentVariable("PROFILE_COMMIT"),
            Framework = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription,
            Architecture = RuntimeInformation.ProcessArchitecture.ToString(),
            Environment.ProcessorCount,
            Cpu = ReadIfExists("/proc/cpuinfo")?.Split('\n').FirstOrDefault(s => s.StartsWith("model name")),
            CpuLimit = ReadIfExists("/sys/fs/cgroup/cpu.max"),
            MemoryLimit = ReadIfExists("/sys/fs/cgroup/memory.max"),
            ServerGC = System.Runtime.GCSettings.IsServerGC,
            TieredCompilation = Environment.GetEnvironmentVariable("DOTNET_TieredCompilation") ?? "runtime-default",
            WarmupOperationsPerScenario = 5,
            Quick, Rounds,
            Notes = "Release, warmed scenarios; process-wide allocations include server allocations for HTTP; peak working set is cumulative. Local Docker is not AWS Fargate."
        };
        object? httpDetails = null;
        object? concurrencyDetails = null;
        object? pharmacyDetails = null;
        try
        {
            if (suite is "all" or "crypto") await CryptoProfiles.RunAsync();
            if (suite == "native-memory")
                await CryptoProfiles.NativeMemoryAsync(Number("--payload-mib", 8), Array.IndexOf(args, "--threshold-mib") < 0 ? null : Number("--threshold-mib", 0));
            if (suite is "all" or "memory") await MemoryProfiles.RunAsync();
            if (suite == "keys") await KeyProfiles.RunAsync();
            if (suite == "soap") await SoapProfiles.RunAsync();
            if (suite is "all" or "http") httpDetails = await HttpProfiles.RunAsync();
            if (suite == "crypto-concurrency")
                concurrencyDetails = await ConcurrentCryptoProfiles.RunAsync(Number("--payload-kib", 8192) * 1024, Number("--concurrency", 4), Number("--requests", Quick ? 8 : 32), Number("--threshold-mib", -1));
            if (suite == "pharmacy")
                pharmacyDetails = await PharmacyProfiles.RunAsync(Number("--concurrency", 4), Number("--requests", Quick ? 8 : 64), Number("--prescribers", 16), Number("--citizen-crl-entries", 350_000), Number("--ehealth-crl-entries", 20_000), Option("--backend", "native") != "bouncycastle");
        }
        finally
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            await File.WriteAllTextAsync(output, JsonSerializer.Serialize(new { metadata, results = Results, httpDetails, concurrencyDetails, pharmacyDetails }, new JsonSerializerOptions { WriteIndented = true }));
        }
    }
    private static string? ReadIfExists(string path) => File.Exists(path) ? File.ReadAllText(path).Trim() : null;

    internal static async Task MeasureAsync(string suite, string scenario, int bytes, int iterations, Func<Task> operation)
    {
        if (Quick) iterations = Math.Min(iterations, 4);
        for (int i = 0; i < 5; i++) await operation();
        for (int round = 1; round <= Rounds; round++)
        {
            GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
            var samples = new double[iterations];
            int gen0 = GC.CollectionCount(0), gen1 = GC.CollectionCount(1), gen2 = GC.CollectionCount(2);
            using var process = Process.GetCurrentProcess();
            long workingSetBefore = process.WorkingSet64;
            var cpuBefore = process.TotalProcessorTime;
            long allocatedBefore = GC.GetTotalAllocatedBytes(true);
            var elapsed = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                long start = Stopwatch.GetTimestamp();
                await operation();
                samples[i] = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            }
            elapsed.Stop();
            long allocated = GC.GetTotalAllocatedBytes(true) - allocatedBefore;
            process.Refresh();
            Array.Sort(samples);
            var result = new Measurement(suite, scenario, bytes, round, iterations,
                elapsed.Elapsed.TotalMilliseconds / iterations,
                samples[iterations / 2], samples[Math.Min(iterations - 1, (int)Math.Ceiling(iterations * .95) - 1)],
                iterations / elapsed.Elapsed.TotalSeconds, allocated / (double)iterations,
                (process.TotalProcessorTime - cpuBefore).TotalMilliseconds / iterations,
                GC.CollectionCount(0) - gen0, GC.CollectionCount(1) - gen1, GC.CollectionCount(2) - gen2,
                workingSetBefore, process.WorkingSet64, process.PeakWorkingSet64);
            Results.Add(result);
            Console.WriteLine($"{suite}/{scenario}/{bytes}: round {round}, {result.MeanMs:F3} ms/op, {result.AllocatedBytesPerOperation:F0} B/op, gen2={result.Gen2}");
        }
    }
}

internal record Measurement(string Suite, string Scenario, int PayloadBytes, int Round, int Iterations,
    double MeanMs, double P50Ms, double P95Ms, double OperationsPerSecond, double AllocatedBytesPerOperation,
    double CpuMsPerOperation, int Gen0, int Gen1, int Gen2, long WorkingSetBefore, long WorkingSetAfter, long ProcessPeakWorkingSet);
