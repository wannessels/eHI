using System;
using System.IO;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Configuration;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    // Length-delimited CMS framing without copying payloads into an AsnWriter buffer.
    // Metadata is still produced/validated by the platform ASN.1 and CMS APIs.
    internal sealed class DerSegments
    {
        private readonly byte? tag;
        private readonly ReadOnlyMemory<byte> bytes;
        private readonly DerSegments[] children;
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

        internal byte[] Encode()
        {
            var result = new byte[checked((int)EncodedLength)];
            using var output = new MemoryStream(result, true); Write(output); return result;
        }
        internal Stream ToStream()
        {
            if (EncodedLength <= Settings.Default.InMemorySize) return new MemoryStream(Encode(), false);
            var stream = new TempFileStreamFactory().CreateNew();
            try { Write(stream); stream.Position = 0; return stream; }
            catch { stream.Dispose(); throw; }
        }
        private void Write(Stream output)
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
