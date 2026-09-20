#if LEGACY_RUNTIME
using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace System.IO
{
    public static class LegacyStreamExtensions
    {
        public static int Read(this Stream stream, Span<byte> destination)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(destination.Length);
            try { int read = stream.Read(buffer, 0, destination.Length); buffer.AsSpan(0, read).CopyTo(destination); return read; }
            finally { ArrayPool<byte>.Shared.Return(buffer, true); }
        }
        public static void Write(this Stream stream, ReadOnlySpan<byte> source)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(source.Length);
            try { source.CopyTo(buffer); stream.Write(buffer, 0, source.Length); }
            finally { ArrayPool<byte>.Shared.Return(buffer, true); }
        }
        public static async ValueTask<int> ReadAsync(this Stream stream, Memory<byte> destination, CancellationToken cancellation = default)
        {
            if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)destination, out var array))
                return await stream.ReadAsync(array.Array, array.Offset, array.Count, cancellation).ConfigureAwait(false);
            byte[] buffer = ArrayPool<byte>.Shared.Rent(destination.Length);
            try { int read = await stream.ReadAsync(buffer, 0, destination.Length, cancellation).ConfigureAwait(false); buffer.AsMemory(0, read).CopyTo(destination); return read; }
            finally { ArrayPool<byte>.Shared.Return(buffer, true); }
        }
        public static async ValueTask WriteAsync(this Stream stream, ReadOnlyMemory<byte> source, CancellationToken cancellation = default)
        {
            if (MemoryMarshal.TryGetArray(source, out var array))
            { await stream.WriteAsync(array.Array, array.Offset, array.Count, cancellation).ConfigureAwait(false); return; }
            byte[] buffer = ArrayPool<byte>.Shared.Rent(source.Length);
            try { source.CopyTo(buffer); await stream.WriteAsync(buffer, 0, source.Length, cancellation).ConfigureAwait(false); }
            finally { ArrayPool<byte>.Shared.Return(buffer, true); }
        }
    }
}
namespace System.Collections.Generic
{
    public static class LegacyDictionaryExtensions
    {
        public static bool TryAdd<TKey, TValue>(this Dictionary<TKey, TValue> dictionary, TKey key, TValue value)
        { if (dictionary.ContainsKey(key)) return false; dictionary.Add(key, value); return true; }
    }
}
#endif
