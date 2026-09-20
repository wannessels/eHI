using System;
using System.IO;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    // Length-delimited CMS framing without copying payloads into an AsnWriter buffer.
    // Metadata is still produced/validated by the platform ASN.1 and CMS APIs.
    internal sealed class DerSegments
    {
        private readonly byte? tag;
        private readonly ReadOnlyMemory<byte> bytes;
        private readonly DerSegments[] children;
        private Stream source;
        private long sourcePosition;
        private readonly long contentLength;
        private long EncodedLength => tag.HasValue ? checked(1 + LengthBytes(contentLength) + contentLength) : contentLength;

        private DerSegments(byte? tag, ReadOnlyMemory<byte> bytes, DerSegments[] children)
        {
            this.tag = tag; this.bytes = bytes; this.children = children;
            contentLength = bytes.Length;
            if (children != null) foreach (var child in children) contentLength = checked(contentLength + child.EncodedLength);
        }
        internal static DerSegments Encoded(ReadOnlyMemory<byte> bytes) => new(null, bytes, null);
        internal static DerSegments Value(byte tag, ReadOnlyMemory<byte> bytes) => new(tag, bytes, null);
        internal static DerSegments Constructed(byte tag, params DerSegments[] children) => new(tag, default, children);
        internal static DerSegments Value(byte tag, Stream source)
        {
            if (source.Position > source.Length) throw new InvalidMessageException("CMS source position exceeds its length");
            var segment = new DerSegments(tag, default, null, source.Length - source.Position);
            segment.source = source; segment.sourcePosition = source.Position; return segment;
        }
        private DerSegments(byte tag, ReadOnlyMemory<byte> bytes, DerSegments[] children, long length)
            : this(tag, bytes, children) { contentLength = length; }

        internal byte[] Encode()
        {
            var result = new byte[checked((int)EncodedLength)];
            using var output = new MemoryStream(result, true); Write(output); return result;
        }
        internal void Write(Stream output)
        {
            OperationScope.Cancellation.ThrowIfCancellationRequested();
            if (tag.HasValue)
            {
                Span<byte> header = stackalloc byte[10]; header[0] = tag.Value;
                int count = LengthBytes(contentLength);
                if (count == 1) header[1] = (byte)contentLength;
                else
                {
                    header[1] = (byte)(0x80 | (count - 1));
                    long length = contentLength;
                    for (int index = count; index >= 2; index--) { header[index] = (byte)length; length >>= 8; }
                }
                output.Write(header.Slice(0, 1 + count));
            }
            var remaining = bytes;
            while (!remaining.IsEmpty)
            {
                OperationScope.Cancellation.ThrowIfCancellationRequested();
                int count = Math.Min(remaining.Length, 81920);
                output.Write(remaining.Span.Slice(0, count)); remaining = remaining.Slice(count);
            }
            if (children != null) foreach (var child in children) child.Write(output);
            if (source != null)
            {
                if (source.Length - sourcePosition != contentLength) throw new InvalidOperationException("CMS source changed length");
                source.Position = sourcePosition; OperationScope.Copy(source, output);
            }
        }
        internal async Task WriteAsync(Stream output)
        {
            var token = OperationScope.Cancellation; token.ThrowIfCancellationRequested();
            if (tag.HasValue)
            {
                byte[] header = new byte[10]; header[0] = tag.Value;
                int count = LengthBytes(contentLength);
                if (count == 1) header[1] = (byte)contentLength;
                else
                {
                    header[1] = (byte)(0x80 | (count - 1)); long length = contentLength;
                    for (int index = count; index >= 2; index--) { header[index] = (byte)length; length >>= 8; }
                }
                await output.WriteAsync(header.AsMemory(0, 1 + count), token).ConfigureAwait(false);
            }
            await output.WriteAsync(bytes, token).ConfigureAwait(false);
            if (children != null) foreach (var child in children) await child.WriteAsync(output).ConfigureAwait(false);
            if (source != null)
            {
                if (source.Length - sourcePosition != contentLength) throw new InvalidOperationException("CMS source changed length");
                source.Position = sourcePosition; await OperationScope.CopyAsync(source, output).ConfigureAwait(false);
            }
        }
        private static int LengthBytes(long length)
        {
            if (length < 128) return 1;
            int count = 1;
            do { count++; length >>= 8; } while (length != 0);
            return count;
        }
    }
}
