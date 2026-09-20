using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal static class NativeStreamingCms
    {
        private const string MessageDigest = "1.2.840.113549.1.9.4", ContentType = "1.2.840.113549.1.9.3";
        internal static byte[] Hash(Stream input, HashAlgorithmName algorithm)
        {
            using var hash = IncrementalHash.CreateHash(algorithm);
            byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                int count;
                while (true)
                {
                    OperationScope.Cancellation.ThrowIfCancellationRequested(); count = input.Read(buffer, 0, buffer.Length);
                    if (count == 0) break; hash.AppendData(buffer, 0, count);
                }
                return hash.GetHashAndReset();
            }
            finally { ArrayPool<byte>.Shared.Return(buffer, true); }
        }
        internal static SignedCms Sign(Stream content, X509Certificate2 certificate, AsymmetricAlgorithm key, byte[] id)
            => SignDigest(Hash(content, HashAlgorithmName.SHA256), certificate, key, id);
        internal static SignedCms SignDigest(byte[] digest, X509Certificate2 certificate, AsymmetricAlgorithm key, byte[] id)
        {
            var attributes = new AsnWriter(AsnEncodingRules.DER);
            using (attributes.PushSetOf())
            {
                using (attributes.PushSequence()) { attributes.WriteObjectIdentifier(ContentType); using (attributes.PushSetOf()) attributes.WriteObjectIdentifier(CryptoEncoding.Data); }
                using (attributes.PushSequence()) { attributes.WriteObjectIdentifier(MessageDigest); using (attributes.PushSetOf()) attributes.WriteOctetString(digest); }
                using (attributes.PushSequence()) { attributes.WriteObjectIdentifier("1.2.840.113549.1.9.5"); using (attributes.PushSetOf()) attributes.WriteEncodedValue(new Pkcs9SigningTime(DateTime.UtcNow).RawData); }
            }
            byte[] signedAttributes = attributes.Encode(); byte[] signature;
            OperationScope.Cancellation.ThrowIfCancellationRequested();
            lock (key)
            {
                signature = key switch
                {
                    RSA rsa => rsa.SignHash(SHA256.HashData(signedAttributes), HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
                    ECDsa ec => ec.SignHash(SHA256.HashData(signedAttributes), DSASignatureFormat.Rfc3279DerSequence),
                    _ => throw new NotSupportedException("RSA or ECDSA signing keys are required")
                };
            }
            signedAttributes[0] = 0xA0; // IMPLICIT signedAttrs; the signature covers the DER SET tag above.
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(CryptoEncoding.SignedData);
                using (writer.PushSequence(CryptoEncoding.Context(0))) using (writer.PushSequence())
                {
                    writer.WriteInteger(certificate == null ? 3 : 1);
                    using (writer.PushSetOf()) CryptoEncoding.WriteAlgorithm(writer, CryptoEncoding.Sha256);
                    using (writer.PushSequence()) writer.WriteObjectIdentifier(CryptoEncoding.Data);
                    using (writer.PushSetOf()) using (writer.PushSequence())
                    {
                        writer.WriteInteger(certificate == null ? 3 : 1);
                        if (certificate == null) writer.WriteOctetString(id, CryptoEncoding.Context(0, false));
                        else using (writer.PushSequence()) { writer.WriteEncodedValue(certificate.IssuerName.RawData); writer.WriteIntegerUnsigned(CryptoEncoding.Serial(certificate)); }
                        CryptoEncoding.WriteAlgorithm(writer, CryptoEncoding.Sha256);
                        writer.WriteEncodedValue(signedAttributes);
                        if (key is RSA)
                        {
                            using (writer.PushSequence())
                            {
                                writer.WriteObjectIdentifier(CryptoEncoding.RsaPss);
                                using (writer.PushSequence())
                                {
                                    using (writer.PushSequence(CryptoEncoding.Context(0))) CryptoEncoding.WriteAlgorithm(writer, CryptoEncoding.Sha256);
                                    using (writer.PushSequence(CryptoEncoding.Context(1))) using (writer.PushSequence())
                                    { writer.WriteObjectIdentifier("1.2.840.113549.1.1.8"); CryptoEncoding.WriteAlgorithm(writer, CryptoEncoding.Sha256); }
                                    using (writer.PushSequence(CryptoEncoding.Context(2))) writer.WriteInteger(32);
                                }
                            }
                        }
                        else CryptoEncoding.WriteAlgorithm(writer, "1.2.840.10045.4.3.2", false);
                        writer.WriteOctetString(signature);
                    }
                }
            }
            var cms = new SignedCms(new ContentInfo(Array.Empty<byte>()), true); cms.Decode(writer.Encode()); return cms;
        }

        internal sealed class Parsed
        {
            internal SignedCms Metadata;
            internal Dictionary<string, byte[]> Digests;
            internal byte[] EncodedSigners;
            internal void Verify(X509Certificate2 certificate, WebKey web)
            {
                var signer = NativeCms.SingleSigner(Metadata);
                if (signer.CounterSignerInfos.Count != 0) throw new CryptographicException("CMS countersignatures are not supported by this eHealth profile");
                // Read the actual encoded signed attributes and signature AlgorithmIdentifier;
                // SignerInfo.SignatureAlgorithm alone omits the RSA-PSS parameters.
                var signerReader = new AsnReader(EncodedSigners, AsnEncodingRules.BER);
                var signers = signerReader.ReadSetOf(true); var info = signers.ReadSequence(); signers.ThrowIfNotEmpty(); signerReader.ThrowIfNotEmpty();
                info.ReadInteger(); info.ReadEncodedValue(); var digestAlgorithm = CryptoEncoding.ReadAlgorithm(info);
                if (!Digests.TryGetValue(digestAlgorithm.Oid, out byte[] digest)) throw new CryptographicException("Signer digest is missing from SignedData");
                if (digestAlgorithm.Parameters != null && !digestAlgorithm.Parameters.AsSpan().SequenceEqual(new byte[] { 5, 0 })) throw new CryptographicException("Unsupported digest parameters");
                byte[] signedAttributes = null;
                if (info.PeekTag().HasSameClassAndValue(CryptoEncoding.Context(0)))
                {
                    signedAttributes = info.ReadEncodedValue().ToArray(); signedAttributes[0] = 0x31;
                    ValidateAttributeEncoding(signedAttributes);
                    byte[] messageDigest = NativeCms.Attribute(signer.SignedAttributes, MessageDigest) ?? throw new CryptographicException("Missing message digest");
                    var digestReader = new AsnReader(messageDigest, AsnEncodingRules.DER);
                    byte[] expected = digestReader.ReadOctetString(); digestReader.ThrowIfNotEmpty();
                    if (!CryptographicOperations.FixedTimeEquals(expected, digest)) throw new CryptographicException("Content digest mismatch");
                    var typeReader = new AsnReader(NativeCms.Attribute(signer.SignedAttributes, ContentType) ?? throw new CryptographicException("Missing content type"), AsnEncodingRules.DER);
                    if (typeReader.ReadObjectIdentifier() != CryptoEncoding.Data) throw new CryptographicException("Content type mismatch"); typeReader.ThrowIfNotEmpty();
                    digest = CryptoEncoding.Hash(digestAlgorithm.Oid, signedAttributes);
                }
                var algorithm = CryptoEncoding.ReadAlgorithm(info); byte[] signature = info.ReadOctetString();
                if (info.HasData) info.ReadSetOf(true, CryptoEncoding.Context(1)); info.ThrowIfNotEmpty();
                ValidateAlgorithmProtection(signer, digestAlgorithm, algorithm);
                using var ownedKey = certificate == null ? null : CertVerifier.PublicKey(certificate);
                var key = ownedKey ?? web.NativeKey;
                OperationScope.Cancellation.ThrowIfCancellationRequested();
                if (!VerifyHash(key, digest, digestAlgorithm.Oid, algorithm, signature)) throw new CryptographicException("Invalid CMS signature");
            }
        }

        private static void ValidateAttributeEncoding(byte[] encoded)
        {
            // RFC 5652 requires DER signedAttrs, including canonical SET ordering.
            var reader = new AsnReader(encoded, AsnEncodingRules.DER); var set = reader.ReadSetOf(); reader.ThrowIfNotEmpty();
            var seen = new HashSet<string>();
            while (set.HasData)
            {
                var attribute = set.ReadSequence(); if (!seen.Add(attribute.ReadObjectIdentifier())) throw new CryptographicException("Duplicate signed attribute");
                var values = attribute.ReadSetOf(); if (!values.HasData) throw new CryptographicException("Empty signed attribute");
                while (values.HasData) values.ReadEncodedValue(); attribute.ThrowIfNotEmpty();
            }
        }
        private static void ValidateAlgorithmProtection(SignerInfo signer, (string Oid, byte[] Parameters) digest, (string Oid, byte[] Parameters) signature)
        {
            byte[] protection = NativeCms.Attribute(signer.SignedAttributes, "1.2.840.113549.1.9.52");
            if (protection == null) return;
            var reader = CryptoEncoding.Sequence(protection);
            var protectedDigest = CryptoEncoding.ReadAlgorithm(reader);
            byte[] protectedSignature = reader.ReadEncodedValue().ToArray(); reader.ThrowIfNotEmpty();
            if (protectedSignature[0] != 0xA1) throw new CryptographicException("Invalid algorithm protection"); protectedSignature[0] = 0x30;
            var algorithm = CryptoEncoding.ReadAlgorithm(new AsnReader(protectedSignature, AsnEncodingRules.DER));
            static bool Same((string Oid, byte[] Parameters) a, (string Oid, byte[] Parameters) b) => a.Oid == b.Oid &&
                (a.Parameters ?? new byte[] { 5, 0 }).AsSpan().SequenceEqual(b.Parameters ?? new byte[] { 5, 0 });
            if (!Same(digest, protectedDigest) || !Same(signature, algorithm)) throw new CryptographicException("CMS algorithm protection mismatch");
        }
        private static bool VerifyHash(AsymmetricAlgorithm key, byte[] digest, string digestOid, (string Oid, byte[] Parameters) algorithm, byte[] signature)
        {
            string expected = algorithm.Oid switch
            {
                CryptoEncoding.Rsa => digestOid,
                "1.2.840.113549.1.1.5" => CryptoEncoding.Sha1,
                "1.2.840.113549.1.1.11" or "1.2.840.10045.4.3.2" => CryptoEncoding.Sha256,
                "1.2.840.113549.1.1.12" or "1.2.840.10045.4.3.3" => CryptoEncoding.Sha384,
                "1.2.840.113549.1.1.13" or "1.2.840.10045.4.3.4" => CryptoEncoding.Sha512,
                CryptoEncoding.RsaPss => CryptoEncoding.ReadPssDigest(algorithm.Parameters),
                _ => throw new CryptographicException("Unsupported signature algorithm")
            };
            if (expected != digestOid) throw new CryptographicException("Signature/digest algorithm mismatch");
            if (algorithm.Oid != CryptoEncoding.RsaPss && algorithm.Parameters != null && !algorithm.Parameters.AsSpan().SequenceEqual(new byte[] { 5, 0 }))
                throw new CryptographicException("Unsupported signature parameters");
            lock (key)
            {
                if (key is RSA rsa && algorithm.Oid.StartsWith("1.2.840.113549.1.1.", StringComparison.Ordinal))
                    return rsa.VerifyHash(digest, signature, CryptoEncoding.HashName(digestOid), algorithm.Oid == CryptoEncoding.RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
                if (key is ECDsa ec && algorithm.Oid.StartsWith("1.2.840.10045.", StringComparison.Ordinal))
                    return ec.VerifyHash(digest, signature, DSASignatureFormat.Rfc3279DerSequence);
                return false;
            }
        }

        internal static Task<Parsed> ReadAsync(Stream input, Stream content) => ReadAsync(input, payload => OperationScope.CopyAsync(payload, content));
        // The consumer reads the hashed payload as it streams; whatever it leaves unread is drained so the digests cover all content.
        internal static async Task<Parsed> ReadAsync(Stream input, Func<Stream, Task> consume)
        {
            var reader = new BerStreamReader(input);
            reader.Enter(0x30); byte[] type = reader.ReadEncoded(); ExpectOid(type, CryptoEncoding.SignedData);
            reader.Enter(0xA0); reader.Enter(0x30);
            byte[] version = reader.ReadEncoded(), algorithms = reader.ReadEncoded();
            var hashes = new Dictionary<string, IncrementalHash>();
            try
            {
                var algorithmReader = new AsnReader(algorithms, AsnEncodingRules.BER); var set = algorithmReader.ReadSetOf(true); algorithmReader.ThrowIfNotEmpty();
                while (set.HasData)
                {
                    var algorithm = CryptoEncoding.ReadAlgorithm(set);
                    if (hashes.ContainsKey(algorithm.Oid)) throw new InvalidMessageException("Duplicate digest algorithm");
                    hashes.Add(algorithm.Oid, IncrementalHash.CreateHash(CryptoEncoding.HashName(algorithm.Oid)));
                }
                reader.Enter(0x30); byte[] contentType = reader.ReadEncoded(); ExpectOid(contentType, CryptoEncoding.Data);
                reader.Enter(0xA0);
                using var payload = new HashReader(reader.OpenOctets(), hashes.Values.ToArray());
                await consume(payload).ConfigureAwait(false);
                await payload.DrainAsync().ConfigureAwait(false);
                reader.Leave(); reader.Leave();
                var fields = new List<DerSegments> { DerSegments.Encoded(version), DerSegments.Encoded(algorithms), DerSegments.Constructed(0x30, DerSegments.Encoded(contentType)) };
                if (reader.HasData && reader.PeekTag() == 0xA0) fields.Add(DerSegments.Encoded(reader.ReadEncoded()));
                if (reader.HasData && reader.PeekTag() == 0xA1) fields.Add(DerSegments.Encoded(reader.ReadEncoded()));
                byte[] signers = reader.ReadEncoded(); fields.Add(DerSegments.Encoded(signers));
                reader.Leave(); reader.Leave(); reader.Leave(); reader.End();
                byte[] metadata = DerSegments.Constructed(0x30, DerSegments.Encoded(type), DerSegments.Constructed(0xA0, DerSegments.Constructed(0x30, fields.ToArray()))).Encode();
                var cms = new SignedCms(new ContentInfo(Array.Empty<byte>()), true); cms.Decode(metadata);
                return new Parsed { Metadata = cms, EncodedSigners = signers, Digests = hashes.ToDictionary(pair => pair.Key, pair => pair.Value.GetHashAndReset()) };
            }
            catch (Exception error) when (error is AsnContentException || error is CryptographicException)
            { throw new InvalidMessageException("Invalid CMS signed message", error); }
            finally { foreach (var hash in hashes.Values) hash.Dispose(); }
        }
        internal static void ExpectOid(byte[] encoded, string expected)
        {
            var reader = new AsnReader(encoded, AsnEncodingRules.BER);
            if (reader.ReadObjectIdentifier() != expected) throw new InvalidMessageException("Unexpected CMS content type"); reader.ThrowIfNotEmpty();
        }
        private sealed class HashReader : Stream
        {
            private readonly Stream input; private readonly IncrementalHash[] hashes;
            internal HashReader(Stream input, IncrementalHash[] hashes) { this.input = input; this.hashes = hashes; }
            private int Append(ReadOnlySpan<byte> buffer, int read) { foreach (var hash in hashes) hash.AppendData(buffer.Slice(0, read)); return read; }
            public override int Read(Span<byte> buffer) => Append(buffer, input.Read(buffer));
            public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
            public override int ReadByte() { Span<byte> one = stackalloc byte[1]; return Read(one) == 0 ? -1 : one[0]; }
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
            { int read = await input.ReadAsync(buffer, token).ConfigureAwait(false); return Append(buffer.Span, read); }
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) => ReadAsync(buffer.AsMemory(offset, count), token).AsTask();
            internal async Task DrainAsync()
            {
                byte[] buffer = ArrayPool<byte>.Shared.Rent(81920);
                try { while (await ReadAsync(buffer.AsMemory(), OperationScope.Cancellation).ConfigureAwait(false) != 0) { } }
                finally { ArrayPool<byte>.Shared.Return(buffer, true); }
            }
            public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() { } public override void Write(byte[] b, int o, int c) => throw new NotSupportedException();
            public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException(); public override void SetLength(long v) => throw new NotSupportedException();
        }
    }
}
