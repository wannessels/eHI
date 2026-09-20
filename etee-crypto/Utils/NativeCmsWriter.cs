using System;
using System.Buffers;
using System.Formats.Asn1;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Threading;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    // BER allows the signature and other small metadata to follow the payload.
    // Only the final result is spooled; nested writers feed hashing/encryption directly.
    internal sealed class BerOctetWriter : Stream
    {
        private readonly Stream output;
        private byte[] buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        private readonly byte[] header = new byte[5];
        private int count;
        private bool completed;
        internal BerOctetWriter(Stream output, byte tag)
        { this.output = output; Begin(output, tag); }
        internal static void Begin(Stream output, byte tag) => output.Write(new byte[] { tag, 0x80 });
        internal static void End(Stream output, int levels) => output.Write(new byte[2 * levels]);
        private int Header()
        {
            header[0] = 0x04;
            if (count < 128) { header[1] = (byte)count; return 2; }
            int bytes = count <= 255 ? 1 : count <= 65535 ? 2 : 3;
            header[1] = (byte)(0x80 | bytes);
            for (int i = 0; i < bytes; i++) header[2 + i] = (byte)(count >> (8 * (bytes - 1 - i)));
            return 2 + bytes;
        }
        private void Chunk()
        {
            if (count == 0) return;
            output.Write(header, 0, Header()); output.Write(buffer, 0, count); count = 0;
        }
        private async ValueTask ChunkAsync(CancellationToken token)
        {
            if (count == 0) return;
            await output.WriteAsync(header.AsMemory(0, Header()), token).ConfigureAwait(false);
            await output.WriteAsync(buffer.AsMemory(0, count), token).ConfigureAwait(false); count = 0;
        }
        public override void Write(byte[] bytes, int offset, int length) => Write(bytes.AsSpan(offset, length));
        public override void Write(ReadOnlySpan<byte> bytes)
        {
            if (completed || buffer == null) throw new ObjectDisposedException(nameof(BerOctetWriter));
            while (!bytes.IsEmpty)
            {
                OperationScope.Cancellation.ThrowIfCancellationRequested();
                int take = Math.Min(bytes.Length, 64 * 1024 - count); bytes.Slice(0, take).CopyTo(buffer.AsSpan(count));
                count += take; bytes = bytes.Slice(take); if (count == 64 * 1024) Chunk();
            }
        }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken token = default)
        {
            if (completed || buffer == null) throw new ObjectDisposedException(nameof(BerOctetWriter));
            while (!bytes.IsEmpty)
            {
                token.ThrowIfCancellationRequested();
                int take = Math.Min(bytes.Length, 64 * 1024 - count); bytes.Slice(0, take).CopyTo(buffer.AsMemory(count));
                count += take; bytes = bytes.Slice(take); if (count == 64 * 1024) await ChunkAsync(token).ConfigureAwait(false);
            }
        }
        public override Task WriteAsync(byte[] bytes, int offset, int length, CancellationToken token)
            => WriteAsync(bytes.AsMemory(offset, length), token).AsTask();
        internal async Task CompleteAsync()
        {
            if (completed) throw new InvalidOperationException("CMS payload already complete");
            await ChunkAsync(OperationScope.Cancellation).ConfigureAwait(false); End(output, 1); completed = true;
        }
        // Abort/dispose returns buffers without finishing an incomplete message or owning output.
        protected override void Dispose(bool disposing)
        { if (disposing && buffer != null) { ArrayPool<byte>.Shared.Return(buffer, true); buffer = null; } base.Dispose(disposing); }
        public override void Flush() => Chunk();
        public override bool CanWrite => buffer != null && !completed; public override bool CanRead => false; public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] b, int o, int c) => throw new NotSupportedException(); public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException(); public override void SetLength(long n) => throw new NotSupportedException();
    }

    internal sealed class NativeSigningWriter : Stream
    {
        private readonly Stream output;
        private readonly IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        private readonly BerOctetWriter payload;
        private bool contentCompleted;
        internal NativeSigningWriter(Stream output, bool certificateSigner)
        {
            this.output = output;
            var oid = new AsnWriter(AsnEncodingRules.DER); oid.WriteObjectIdentifier(CryptoEncoding.SignedData);
            BerOctetWriter.Begin(output, 0x30); output.Write(oid.Encode()); BerOctetWriter.Begin(output, 0xA0); BerOctetWriter.Begin(output, 0x30);
            var prefix = new AsnWriter(AsnEncodingRules.DER); prefix.WriteInteger(certificateSigner ? 1 : 3);
            using (prefix.PushSetOf()) CryptoEncoding.WriteAlgorithm(prefix, CryptoEncoding.Sha256); output.Write(prefix.Encode());
            BerOctetWriter.Begin(output, 0x30); oid.Reset(); oid.WriteObjectIdentifier(CryptoEncoding.Data); output.Write(oid.Encode());
            BerOctetWriter.Begin(output, 0xA0); payload = new BerOctetWriter(output, 0x24);
        }
        public override void Write(byte[] bytes, int offset, int count) => Write(bytes.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> bytes) { hash.AppendData(bytes); payload.Write(bytes); }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken token = default)
        { hash.AppendData(bytes.Span); return payload.WriteAsync(bytes, token); }
        public override Task WriteAsync(byte[] bytes, int offset, int count, CancellationToken token) => WriteAsync(bytes.AsMemory(offset, count), token).AsTask();
        internal async Task<byte[]> CompleteContentAsync()
        {
            await payload.CompleteAsync().ConfigureAwait(false); BerOctetWriter.End(output, 2); contentCompleted = true;
            return hash.GetHashAndReset();
        }
        internal void CompleteMetadata(SignedCms metadata)
        {
            if (!contentCompleted) throw new InvalidOperationException("CMS content is incomplete");
            var top = CryptoEncoding.Sequence(metadata.Encode()); top.ReadObjectIdentifier(); var wrapper = top.ReadSequence(CryptoEncoding.Context(0));
            var signed = wrapper.ReadSequence(); signed.ReadInteger(); signed.ReadSetOf(); signed.ReadSequence();
            while (signed.HasData) output.Write(signed.ReadEncodedValue().Span);
            wrapper.ThrowIfNotEmpty(); top.ThrowIfNotEmpty(); BerOctetWriter.End(output, 3);
        }
        protected override void Dispose(bool disposing) { if (disposing) { payload.Dispose(); hash.Dispose(); } base.Dispose(disposing); }
        public override void Flush() => payload.Flush();
        public override bool CanWrite => payload.CanWrite; public override bool CanRead => false; public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] b, int o, int c) => throw new NotSupportedException(); public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException(); public override void SetLength(long n) => throw new NotSupportedException();
    }
}
