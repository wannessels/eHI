using Egelke.EHealth.Client.Pki;
using Microsoft.IO;

internal static class MemoryProfiles
{
    internal static async Task RunAsync()
    {
        var pool = new RecyclableMemoryStreamManager(new RecyclableMemoryStreamManager.Options
        {
            BlockSize = 64 * 1024, LargeBufferMultiple = 1024 * 1024,
            MaximumBufferSize = 16 * 1024 * 1024,
            MaximumLargePoolFreeBytes = 64 * 1024 * 1024,
            MaximumSmallPoolFreeBytes = 64 * 1024 * 1024,
            ZeroOutBuffer = true
        });
        foreach (int size in new[] { 32 * 1024, 1024 * 1024, 8 * 1024 * 1024 })
        {
            byte[] payload = new byte[size]; new Random(42).NextBytes(payload);
            var factories = new (string Name, Func<MemoryStream> Create)[]
            {
                ("growing", () => new MemoryStream()),
                ("size-hint", () => new MemoryStream(size + 16 * 1024)),
                ("recyclable-zeroed", () => pool.GetStream("profile", size + 16 * 1024))
            };
            foreach (var mode in factories)
            {
                await Program.MeasureAsync("stream-pipeline", mode.Name, size, size > 1024 * 1024 ? 40 : 150, () =>
                {
                    using var input = new MemoryStream(payload, false);
                    using var inner = mode.Create(); using var encrypted = mode.Create(); using var outer = mode.Create();
                    OperationScope.Copy(input, inner); inner.Position = 0;
                    OperationScope.Copy(inner, encrypted); encrypted.Position = 0;
                    OperationScope.Copy(encrypted, outer);
                    byte[] result = outer.ToArray();
                    if (result.Length != size || result[size - 1] != payload[size - 1]) throw new Exception("Buffer corruption");
                    return Task.CompletedTask;
                });
            }
        }
    }
}
