using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Configuration;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    // A bounded BER framing reader. Small metadata is passed to System.Formats.Asn1;
    // OCTET STRING content is copied incrementally, including nested BER chunks.
    internal sealed class BerStreamReader
    {
        private readonly Stream input;
        private readonly Stack<(long? End, long Limit)> frames = new();
        private long position;
        private int peek = -1;
        private int metadataRemaining = Settings.Default.MaximumNativeMetadataSize;
        private long Position => position - (peek >= 0 ? 1 : 0);
        private long Limit => frames.Count == 0 ? long.MaxValue : frames.Peek().Limit;
        internal BerStreamReader(Stream input) { this.input = input; }
        private static InvalidMessageException Invalid() => new("Invalid or truncated CMS framing");
        private int Byte()
        {
            OperationScope.Cancellation.ThrowIfCancellationRequested();
            if (peek >= 0) { int value = peek; peek = -1; return value; }
            if (position >= Limit) throw Invalid();
            int result = input.ReadByte(); if (result < 0) throw Invalid(); position++; return result;
        }
        internal int PeekTag()
        {
            if (peek < 0) peek = Byte();
            return peek;
        }
        private (int Tag, long? Length, byte[] Encoded) Header()
        {
            Span<byte> header = stackalloc byte[16]; int size = 0;
            int tag = Byte(); header[size++] = (byte)tag;
            if ((tag & 31) == 31)
            {
                int value;
                do { if (size >= 7) throw Invalid(); value = Byte(); header[size++] = (byte)value; } while ((value & 128) != 0);
            }
            int first = Byte(); header[size++] = (byte)first;
            if (first == 0x80)
            {
                if ((tag & 32) == 0) throw Invalid();
                return (tag, null, header.Slice(0, size).ToArray());
            }
            long length = first;
            if (first > 0x80)
            {
                int count = first & 127; if (count > 8) throw Invalid(); length = 0;
                for (int i = 0; i < count; i++)
                {
                    int value = Byte(); header[size++] = (byte)value;
                    if (length > (long.MaxValue - value) / 256) throw Invalid(); length = length * 256 + value;
                }
            }
            if (length > Limit - Position) throw Invalid();
            return (tag, length, header.Slice(0, size).ToArray());
        }
        private void Enter(long? length)
        {
            if (frames.Count >= 32) throw new InvalidMessageException("CMS nesting limit exceeded");
            long limit = Limit;
            long? end = length.HasValue ? checked(Position + length.Value) : null;
            frames.Push((end, end ?? limit));
        }
        internal void Enter(int tag)
        {
            var header = Header(); if (header.Tag != tag || (tag & 32) == 0) throw Invalid(); Enter(header.Length);
        }
        internal bool HasData => frames.Peek().End.HasValue ? Position < frames.Peek().End : PeekTag() != 0;
        internal void Leave()
        {
            var frame = frames.Peek();
            if (frame.End.HasValue) { if (Position != frame.End) throw Invalid(); }
            else if (Byte() != 0 || Byte() != 0) throw Invalid();
            frames.Pop();
        }
        internal void End()
        {
            if (frames.Count != 0 || peek >= 0 || input.ReadByte() != -1) throw new InvalidMessageException("Trailing CMS data");
        }
        private void Copy(Stream output, long count, byte[] buffer)
        {
            if (count < 0 || count > Limit - Position || peek >= 0) throw Invalid();
            while (count > 0)
            {
                OperationScope.Cancellation.ThrowIfCancellationRequested();
                int read = input.Read(buffer, 0, (int)Math.Min(count, buffer.Length));
                if (read == 0) throw Invalid(); position += read; count -= read; output.Write(buffer, 0, read);
            }
        }
        internal byte[] ReadEncoded()
        {
            using var output = new MemoryStream();
            byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
            try { CopyMetadata(output, Header(), buffer); return output.ToArray(); }
            finally { ArrayPool<byte>.Shared.Return(buffer, true); }
        }
        private void Charge(long count)
        {
            if (count < 0 || count > metadataRemaining) throw new InvalidMessageException("CMS metadata limit exceeded");
            metadataRemaining -= (int)count;
        }
        private void CopyMetadata(Stream output, (int Tag, long? Length, byte[] Encoded) header, byte[] buffer)
        {
            if (header.Tag == 0) throw Invalid();
            Charge(header.Encoded.Length); output.Write(header.Encoded);
            if ((header.Tag & 32) == 0) { Charge(header.Length.Value); Copy(output, header.Length.Value, buffer); return; }
            if (header.Length.HasValue && header.Length.Value > metadataRemaining) throw new InvalidMessageException("CMS metadata limit exceeded");
            Enter(header.Length);
            while (HasData) CopyMetadata(output, Header(), buffer);
            Leave(); if (!header.Length.HasValue) { Charge(2); output.WriteByte(0); output.WriteByte(0); }
        }
        internal OctetStream OpenOctets(int primitiveTag = 0x04) => new(this, primitiveTag);
        internal sealed class OctetStream : RuntimeStream
        {
            private readonly BerStreamReader reader;
            private long remaining;
            private int depth;
            internal bool Finished { get; private set; }
            internal OctetStream(BerStreamReader reader, int tag) { this.reader = reader; Segment(tag); }
            private void Segment(int tag)
            {
                var header = reader.Header();
                if (header.Tag == tag && header.Length.HasValue) { remaining = header.Length.Value; return; }
                if (header.Tag != (tag | 32)) throw Invalid(); reader.Enter(header.Length); depth++;
            }
            private bool Advance()
            {
                if (Finished) return false;
                while (remaining == 0)
                {
                    if (depth == 0) { Finished = true; return false; }
                    if (reader.HasData) Segment(0x04);
                    else { reader.Leave(); depth--; }
                }
                return true;
            }
            public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
            public override int Read(Span<byte> buffer)
            {
                OperationScope.Cancellation.ThrowIfCancellationRequested();
                if (buffer.IsEmpty || !Advance()) return 0;
                int read = reader.input.Read(buffer.Slice(0, (int)Math.Min(buffer.Length, remaining)));
                if (read == 0) throw Invalid(); reader.position += read; remaining -= read; return read;
            }
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
            {
                token.ThrowIfCancellationRequested();
                if (buffer.IsEmpty || !Advance()) return 0;
                int read = await reader.input.ReadAsync(buffer.Slice(0, (int)Math.Min(buffer.Length, remaining)), token).ConfigureAwait(false);
                if (read == 0) throw Invalid(); reader.position += read; remaining -= read; return read;
            }
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) => ReadAsync(buffer.AsMemory(offset, count), token).AsTask();
            public override bool CanRead => true; public override bool CanWrite => false; public override bool CanSeek => false;
            public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() { } public override void Write(byte[] b, int o, int c) => throw new NotSupportedException();
            public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException(); public override void SetLength(long n) => throw new NotSupportedException();
        }
    }
}
