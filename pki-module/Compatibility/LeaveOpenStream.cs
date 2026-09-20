#if LEGACY_RUNTIME
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki.Compatibility
{
    internal sealed class LeaveOpenStream : Stream
    {
        private readonly Stream inner;
        internal LeaveOpenStream(Stream inner) { this.inner = inner; }
        public override bool CanRead => inner.CanRead;
        public override bool CanWrite => inner.CanWrite;
        public override bool CanSeek => inner.CanSeek;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
        public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellation) => inner.ReadAsync(buffer, offset, count, cancellation);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellation) => inner.WriteAsync(buffer, offset, count, cancellation);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long length) => inner.SetLength(length);
    }
}
#endif
