using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>Stream base exposing the same span/memory hooks on every supported target.</summary>
    public abstract class RuntimeStream : Stream
    {
#if LEGACY_RUNTIME
        public virtual int Read(Span<byte> buffer) => LegacyStreamExtensions.Read(this, buffer);
        public virtual void Write(ReadOnlySpan<byte> buffer) => LegacyStreamExtensions.Write(this, buffer);
        public virtual ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellation = default) => LegacyStreamExtensions.ReadAsync(this, buffer, cancellation);
        public virtual ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellation = default) => LegacyStreamExtensions.WriteAsync(this, buffer, cancellation);
#endif
    }
}
