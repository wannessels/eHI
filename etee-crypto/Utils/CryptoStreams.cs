using Microsoft.IO;
using System.Diagnostics;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Configuration;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    // Every stage can grow independently; encrypted/CMS overhead and unknown input
    // lengths must not allow a stage to silently exceed the memory threshold.
    internal sealed class CryptoSpool : RuntimeStream
    {
        private static readonly RecyclableMemoryStreamManager pool = CreatePool();
        private Stream storage;
        private readonly long threshold = Math.Max(0, Settings.Default.InMemorySize);
        internal CryptoSpool(long expectedLength = 0)
        {
            if (expectedLength > threshold) storage = new WindowsTempFileStream(true);
            else storage = pool.GetStream("spool", expectedLength > 0 ? Math.Min(threshold, expectedLength + 16 * 1024) : 0);
            EHealthMetrics.Spools.Add(1, Storage());
        }
        private static RecyclableMemoryStreamManager CreatePool()
        {
            var manager = new RecyclableMemoryStreamManager(new RecyclableMemoryStreamManager.Options
            {
                BlockSize = 256 * 1024, MaximumSmallPoolFreeBytes = Math.Max(0, Settings.Default.SpoolPoolBytes), MaximumLargePoolFreeBytes = 0, ZeroOutBuffer = true
            });
            EHealthMetrics.Meter.CreateObservableGauge("ehealth.spool.pool.bytes", () => manager.SmallPoolInUseSize, "By", "Pooled spool memory in use");
            EHealthMetrics.Meter.CreateObservableGauge("ehealth.spool.pool.free.bytes", () => manager.SmallPoolFreeSize, "By", "Pooled spool memory kept for reuse");
            return manager;
        }
        private TagList Storage() => new TagList { { "storage", storage is MemoryStream ? "memory" : "file" } };
        internal static long Remaining(Stream stream) => stream.CanSeek ? Math.Max(0, stream.Length - stream.Position) : 0;
        private void Reserve(int count)
        {
            if (storage is MemoryStream && Math.Max(storage.Length, checked(storage.Position + count)) > threshold)
            {
                var file = new WindowsTempFileStream(true);
                try { long position = storage.Position; storage.Position = 0; OperationScope.Copy(storage, file); file.Position = position; }
                catch { file.Dispose(); throw; }
                storage.Dispose(); storage = file; EHealthMetrics.SpoolSpills.Add(1);
            }
        }
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer) { Reserve(buffer.Length); storage.Write(buffer); EHealthMetrics.SpoolBytes.Add(buffer.Length, Storage()); }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
        {
            if (storage is MemoryStream && Math.Max(storage.Length, checked(storage.Position + buffer.Length)) > threshold)
            {
                var file = new WindowsTempFileStream(true);
                try { long position = storage.Position; storage.Position = 0; await storage.CopyToAsync(file, 81920, token).ConfigureAwait(false); file.Position = position; }
                catch { file.Dispose(); throw; }
                storage.Dispose(); storage = file; EHealthMetrics.SpoolSpills.Add(1);
            }
            await storage.WriteAsync(buffer, token).ConfigureAwait(false);
            EHealthMetrics.SpoolBytes.Add(buffer.Length, Storage());
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token) => WriteAsync(buffer.AsMemory(offset, count), token).AsTask();
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) => storage.ReadAsync(buffer, token);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) => storage.ReadAsync(buffer, offset, count, token);
        public override int Read(byte[] buffer, int offset, int count) => storage.Read(buffer, offset, count);
        public override int Read(Span<byte> buffer) => storage.Read(buffer);
        public override int ReadByte() => storage.ReadByte();
        public override long Seek(long offset, SeekOrigin origin) => storage.Seek(offset, origin);
        public override void SetLength(long value)
        {
            if (value > storage.Length) throw new NotSupportedException("Spools grow through writes");
            storage.SetLength(value);
        }
        public override long Position { get => storage.Position; set => storage.Position = value; }
        public override long Length => storage.Length;
        public override bool CanRead => storage.CanRead;
        public override bool CanWrite => storage.CanWrite;
        public override bool CanSeek => storage.CanSeek;
        public override void Flush() => storage.Flush();
        protected override void Dispose(bool disposing) { if (disposing) storage.Dispose(); base.Dispose(disposing); }
    }
}
