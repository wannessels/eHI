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
    internal sealed class CryptoSpool : Stream
    {
        private Stream storage = new MemoryStream();
        private readonly long threshold = Math.Max(0, Settings.Default.InMemorySize);
        internal CryptoSpool(long expectedLength = 0)
        {
            if (expectedLength > threshold) { storage.Dispose(); storage = new WindowsTempFileStream(true); }
            else if (expectedLength > 0 && expectedLength <= int.MaxValue)
            {
                // Reserve the known payload plus modest CMS overhead without repeated
                // MemoryStream growth/LOH copies when the configured budget permits it.
                long capacity = Math.Min(threshold, expectedLength + 16 * 1024);
                if (capacity <= int.MaxValue) { storage.Dispose(); storage = new MemoryStream((int)capacity); }
            }
        }
        internal static long Remaining(Stream stream) => stream.CanSeek ? Math.Max(0, stream.Length - stream.Position) : 0;
        private void Reserve(int count)
        {
            if (storage is MemoryStream && Math.Max(storage.Length, checked(storage.Position + count)) > threshold)
            {
                var file = new WindowsTempFileStream(true);
                try { long position = storage.Position; storage.Position = 0; OperationScope.Copy(storage, file); file.Position = position; }
                catch { file.Dispose(); throw; }
                storage.Dispose(); storage = file;
            }
        }
        public override void Write(byte[] buffer, int offset, int count) { Reserve(count); storage.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer) { Reserve(buffer.Length); storage.Write(buffer); }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default)
        {
            if (storage is MemoryStream && Math.Max(storage.Length, checked(storage.Position + buffer.Length)) > threshold)
            {
                var file = new WindowsTempFileStream(true);
                try { long position = storage.Position; storage.Position = 0; await storage.CopyToAsync(file, 81920, token).ConfigureAwait(false); file.Position = position; }
                catch { file.Dispose(); throw; }
                storage.Dispose(); storage = file;
            }
            await storage.WriteAsync(buffer, token).ConfigureAwait(false);
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
