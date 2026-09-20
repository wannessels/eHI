using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using Egelke.EHealth.Client.Pki;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    internal static class NativeCms
    {
        internal static byte[] Read(Stream input)
        {
            OperationScope.Cancellation.ThrowIfCancellationRequested();
            if (input.CanSeek)
            {
                long remaining = input.Length - input.Position;
                if (remaining < 0 || remaining > int.MaxValue) throw new InvalidMessageException("Message exceeds the platform CMS buffer limit");
                var data = new byte[(int)remaining]; int offset = 0;
                while (offset < data.Length)
                {
                    OperationScope.Cancellation.ThrowIfCancellationRequested();
                    int read = input.Read(data, offset, Math.Min(81920, data.Length - offset));
                    if (read == 0) throw new EndOfStreamException(); offset += read;
                }
                return data;
            }
            using var output = new MemoryStream(); OperationScope.Copy(input, output); return output.ToArray();
        }
        internal static SignedCms Decode(byte[] value)
        {
            try
            {
                var framed = new AsnReader(value, AsnEncodingRules.BER); framed.ReadEncodedValue(); framed.ThrowIfNotEmpty();
                var cms = new SignedCms(); cms.Decode(value);
                if (cms.ContentInfo.ContentType.Value != CryptoEncoding.Data) throw new InvalidMessageException("Unexpected signed content type");
                return cms;
            }
            catch (Exception error) when (error is CryptographicException || error is AsnContentException)
            { throw new InvalidMessageException("Invalid CMS signed message", error); }
        }
        internal static X509Certificate2Collection LoadCertificates(byte[] certificateSet)
        {
            var certificates = new X509Certificate2Collection();
            if (certificateSet == null) return certificates;
            var set = new AsnReader(certificateSet, AsnEncodingRules.BER).ReadSetOf(true, CryptoEncoding.Context(0));
            while (set.HasData)
            {
                if (set.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence)) certificates.Add(CertificateCache.Load(set.ReadEncodedValue().Span));
                else set.ReadEncodedValue();
            }
            return certificates;
        }
        internal static byte[] CertificateSet(byte[] signedData)
        {
            var top = CryptoEncoding.Sequence(signedData, AsnEncodingRules.BER); top.ReadObjectIdentifier();
            var signed = top.ReadSequence(CryptoEncoding.Context(0)).ReadSequence();
            signed.ReadInteger(); signed.ReadSetOf(true); signed.ReadSequence();
            return signed.HasData && signed.PeekTag().HasSameClassAndValue(CryptoEncoding.Context(0)) ? signed.ReadEncodedValue().ToArray() : null;
        }
        internal static SignerInfo SingleSigner(SignedCms cms)
        {
            if (cms.SignerInfos.Count != 1) throw new InvalidMessageException("An eHealth message must contain exactly one signer");
            return cms.SignerInfos[0];
        }
        internal static byte[] KeyId(SignerInfo signer) => signer.SignerIdentifier.Type == SubjectIdentifierType.SubjectKeyIdentifier ? Convert.FromHexString((string)signer.SignerIdentifier.Value) : null;
        internal static bool Matches(SignerInfo signer, X509Certificate2 cert)
        {
            if (signer.SignerIdentifier.Type == SubjectIdentifierType.SubjectKeyIdentifier) return CryptoEncoding.SubjectKeyIdentifier(cert).AsSpan().SequenceEqual(KeyId(signer));
            if (signer.SignerIdentifier.Type != SubjectIdentifierType.IssuerAndSerialNumber) return false;
            var id = (X509IssuerSerial)signer.SignerIdentifier.Value;
            return CryptoEncoding.SerialKey(CryptoEncoding.Serial(cert)) == CryptoEncoding.SerialKey(Convert.FromHexString(id.SerialNumber)) &&
                CryptoEncoding.NamesEqual(new X500DistinguishedName(id.IssuerName).RawData, cert.IssuerName.RawData);
        }
        internal static X509Certificate2 FindSigner(SignedCms cms, X509Certificate2Collection certificates)
        {
            var signer = SingleSigner(cms); var matches = certificates.Cast<X509Certificate2>().Where(c => Matches(signer, c)).ToArray();
            if (matches.Length > 1) throw new InvalidMessageException("Ambiguous CMS signer certificate");
            return matches.SingleOrDefault();
        }
        internal static DateTime? SigningTime(SignerInfo signer)
        {
            var value = Attribute(signer.SignedAttributes, "1.2.840.113549.1.9.5");
            if (value == null) return null;
            var reader = new AsnReader(value, AsnEncodingRules.DER); var time = CryptoEncoding.ReadTime(reader); reader.ThrowIfNotEmpty(); return time;
        }
        internal static byte[] Attribute(CryptographicAttributeObjectCollection attributes, string oid)
        {
            var matches = attributes.Cast<CryptographicAttributeObject>().Where(a => a.Oid.Value == oid).ToArray();
            if (matches.Length == 0) return null;
            if (matches.Length != 1 || matches[0].Values.Count != 1) throw new InvalidMessageException("Ambiguous CMS attribute: " + oid);
            return matches[0].Values[0].RawData;
        }
        internal static void SetUnsigned(SignerInfo signer, string oid, byte[] value)
        {
            foreach (var attribute in signer.UnsignedAttributes.Cast<CryptographicAttributeObject>().Where(a => a.Oid.Value == oid).ToArray())
                foreach (AsnEncodedData old in attribute.Values) signer.RemoveUnsignedAttribute(old);
            signer.AddUnsignedAttribute(new AsnEncodedData(new Oid(oid), value));
        }
        // SignedCms needs an X.509 public-key carrier for SKI signers. This certificate is never
        // embedded or trusted: only the caller-provided key verifies the message signature.
        internal static X509Certificate2 KeyCarrier(AsymmetricAlgorithm key, byte[] id)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                using (writer.PushSequence())
                {
                    using (writer.PushSequence(CryptoEncoding.Context(0))) writer.WriteInteger(2);
                    writer.WriteInteger(1); CryptoEncoding.WriteAlgorithm(writer, "1.2.840.113549.1.1.11");
                    writer.WriteEncodedValue(new X500DistinguishedName("CN=Key identifier carrier").RawData);
                    using (writer.PushSequence()) { writer.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1)); writer.WriteUtcTime(DateTimeOffset.UtcNow.AddYears(1)); }
                    writer.WriteEncodedValue(new X500DistinguishedName("CN=Key identifier carrier").RawData);
                    writer.WriteEncodedValue(key.ExportSubjectPublicKeyInfo());
                    using (writer.PushSequence(CryptoEncoding.Context(3))) using (writer.PushSequence()) using (writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier("2.5.29.14"); var ski = new AsnWriter(AsnEncodingRules.DER); ski.WriteOctetString(id); writer.WriteOctetString(ski.Encode());
                    }
                }
                CryptoEncoding.WriteAlgorithm(writer, "1.2.840.113549.1.1.11"); writer.WriteBitString(new byte[] { 0 });
            }
            return new X509Certificate2(writer.Encode());
        }
        internal static DerSegments Attach(SignedCms detached, Stream content)
        {
            if (!detached.Detached) throw new ArgumentException("Expected detached signature metadata", nameof(detached));
            var top = CryptoEncoding.Sequence(detached.Encode());
            var type = top.ReadEncodedValue();
            var explicitValue = top.ReadSequence(CryptoEncoding.Context(0));
            var signed = explicitValue.ReadSequence();
            var version = signed.ReadEncodedValue(); var algorithms = signed.ReadEncodedValue();
            var encapsulated = signed.ReadSequence(); var contentType = encapsulated.ReadEncodedValue(); encapsulated.ThrowIfNotEmpty();
            var fields = new List<DerSegments>
            {
                DerSegments.Encoded(version), DerSegments.Encoded(algorithms),
                DerSegments.Constructed(0x30, DerSegments.Encoded(contentType), DerSegments.Constructed(0xA0, DerSegments.Value(0x04, content)))
            };
            while (signed.HasData) fields.Add(DerSegments.Encoded(signed.ReadEncodedValue()));
            explicitValue.ThrowIfNotEmpty(); top.ThrowIfNotEmpty();
            return DerSegments.Constructed(0x30, DerSegments.Encoded(type), DerSegments.Constructed(0xA0, DerSegments.Constructed(0x30, fields.ToArray())));
        }
        internal static (List<CertificateRevocationList> Crls, List<OcspResponse> Ocsps) RevocationValues(SignerInfo signer)
        {
            var crls = new List<CertificateRevocationList>(); var ocsps = new List<OcspResponse>();
            var value = Attribute(signer.UnsignedAttributes, CryptoEncoding.RevocationAttribute); if (value == null) return (crls, ocsps);
            var reader = CryptoEncoding.Sequence(value);
            if (reader.HasData && reader.PeekTag().HasSameClassAndValue(CryptoEncoding.Context(0)))
            { var wrapper = reader.ReadSequence(CryptoEncoding.Context(0)); var list = wrapper.ReadSequence(); while (list.HasData) crls.Add(CertificateRevocationList.Parse(list.ReadEncodedValue().ToArray())); wrapper.ThrowIfNotEmpty(); }
            if (reader.HasData && reader.PeekTag().HasSameClassAndValue(CryptoEncoding.Context(1)))
            { var wrapper = reader.ReadSequence(CryptoEncoding.Context(1)); var list = wrapper.ReadSequence(); while (list.HasData) ocsps.Add(OcspResponse.Parse(list.ReadEncodedValue().ToArray())); wrapper.ThrowIfNotEmpty(); }
            reader.ThrowIfNotEmpty(); return (crls, ocsps);
        }
        internal static byte[] EncodeRevocationValues(IEnumerable<CertificateRevocationList> crls, IEnumerable<OcspResponse> ocsps)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                using (writer.PushSequence(CryptoEncoding.Context(0))) using (writer.PushSequence()) foreach (var crl in crls) writer.WriteEncodedValue(crl.GetEncoded());
                using (writer.PushSequence(CryptoEncoding.Context(1))) using (writer.PushSequence()) foreach (var ocsp in ocsps) writer.WriteEncodedValue(ocsp.GetEncoded());
            }
            return writer.Encode();
        }
    }

    internal static class NativeEnvelope
    {
        private const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
        private static string WrapOid(int size) => size switch { 16 => "2.16.840.1.101.3.4.1.5", 24 => "2.16.840.1.101.3.4.1.25", 32 => "2.16.840.1.101.3.4.1.45", _ => throw new CryptographicException("Unsupported AES key size") };
        internal static EncryptionSession OpenEncryption(Stream output, X509Certificate2[] certificates, WebKey[] webKeys, SecretKey secret)
        {
            var aes = Aes.Create(); aes.KeySize = 128; aes.GenerateKey(); aes.GenerateIV();
            byte[] key = aes.Key;
            try
            {
                var recipients = new List<byte[]>();
                foreach (var cert in certificates ?? Array.Empty<X509Certificate2>())
                {
                    using var publicKey = cert.GetRSAPublicKey(); if (publicKey == null) throw new CryptographicException("Recipient certificate must use RSA");
                    recipients.Add(KeyTransport(publicKey, key, cert, null));
                }
                foreach (var web in webKeys ?? Array.Empty<WebKey>())
                { if (!(web.NativeKey is RSA rsa)) throw new CryptographicException("Recipient WebKey must use RSA"); recipients.Add(KeyTransport(rsa, key, null, web.Id)); }
                if (secret != null)
                {
                    using var wrap = Aes.Create(); wrap.Key = secret.NativeKey;
                    var recipient = new AsnWriter(AsnEncodingRules.DER);
                    using (recipient.PushSequence(CryptoEncoding.Context(2)))
                    {
                        recipient.WriteInteger(4); using (recipient.PushSequence()) recipient.WriteOctetString(secret.Id);
                        CryptoEncoding.WriteAlgorithm(recipient, WrapOid(wrap.KeySize / 8), false);
                        recipient.WriteOctetString(EncryptedXml.EncryptKey(key, wrap));
                    }
                    recipients.Add(recipient.Encode());
                }
                if (recipients.Count == 0) throw new ArgumentException("At least one recipient is required");
                OperationScope.Cancellation.ThrowIfCancellationRequested();
                var type = new AsnWriter(AsnEncodingRules.DER); type.WriteObjectIdentifier(CryptoEncoding.EnvelopedData);
                var version = new AsnWriter(AsnEncodingRules.DER); version.WriteInteger(secret == null && (webKeys == null || webKeys.Length == 0) ? 0 : 2);
                var recipientSet = new AsnWriter(AsnEncodingRules.DER);
                using (recipientSet.PushSetOf()) foreach (var recipient in recipients) recipientSet.WriteEncodedValue(recipient);
                var contentType = new AsnWriter(AsnEncodingRules.DER); contentType.WriteObjectIdentifier(CryptoEncoding.Data);
                var algorithm = new AsnWriter(AsnEncodingRules.DER);
                using (algorithm.PushSequence()) { algorithm.WriteObjectIdentifier(Aes128Cbc); algorithm.WriteOctetString(aes.IV); }
                BerOctetWriter.Begin(output, 0x30); output.Write(type.Encode());
                BerOctetWriter.Begin(output, 0xA0); BerOctetWriter.Begin(output, 0x30);
                output.Write(version.Encode()); output.Write(recipientSet.Encode());
                BerOctetWriter.Begin(output, 0x30); output.Write(contentType.Encode()); output.Write(algorithm.Encode());
                return new EncryptionSession(aes, output);
            }
            catch { aes.Dispose(); throw; }
            finally { CryptographicOperations.ZeroMemory(key); }
        }
        internal sealed class EncryptionSession : IDisposable
        {
            private readonly Aes aes;
            private readonly Stream output;
            private readonly BerOctetWriter payload;
            private readonly ICryptoTransform transform;
            internal CryptoStream Content { get; }
            internal EncryptionSession(Aes aes, Stream output)
            {
                this.aes = aes; this.output = output;
                payload = new BerOctetWriter(output, 0xA0);
                transform = aes.CreateEncryptor(); Content = new CryptoStream(payload, transform, CryptoStreamMode.Write, true);
            }
            internal async System.Threading.Tasks.Task CompleteAsync()
            {
                await Content.FlushFinalBlockAsync(OperationScope.Cancellation).ConfigureAwait(false);
                await payload.CompleteAsync().ConfigureAwait(false); BerOctetWriter.End(output, 4);
            }
            public void Dispose()
            {
                try { Content.Dispose(); }
                finally { payload.Dispose(); transform.Dispose(); aes.Dispose(); }
            }
        }
        private static byte[] KeyTransport(RSA rsa, byte[] key, X509Certificate2 cert, byte[] id)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                writer.WriteInteger(id == null ? 0 : 2);
                if (id == null) using (writer.PushSequence()) { writer.WriteEncodedValue(cert.IssuerName.RawData); writer.WriteIntegerUnsigned(CryptoEncoding.Serial(cert)); }
                else writer.WriteOctetString(id, CryptoEncoding.Context(0, false));
                CryptoEncoding.WriteAlgorithm(writer, CryptoEncoding.Rsa);
                lock (rsa) writer.WriteOctetString(rsa.Encrypt(key, RSAEncryptionPadding.Pkcs1));
            }
            return writer.Encode();
        }
        internal sealed class Decryption : IDisposable
        {
            internal byte[] KeyId;
            internal X509Certificate2[] Candidates = Array.Empty<X509Certificate2>();
            internal AsymmetricAlgorithm PublicKey;
            internal string KeyAlgorithm;
            internal int KeySize;
            internal CryptoStream Content;
            internal BerStreamReader Framing;
            internal Aes Aes;
            internal ICryptoTransform Transform;
            // Matching certificates share the recipient key; the reported one is chosen once the signing time is known.
            internal X509Certificate2 SelectCertificate(DateTime date)
                => Candidates.OrderByDescending(c => CryptoEncoding.ValidAt(c, date)).ThenByDescending(c => c.NotBefore).FirstOrDefault();
            internal void Complete()
            {
                if (Content.ReadByte() != -1) throw new InvalidMessageException("Unexpected decrypted trailing content");
                Framing.Leave(); Framing.Leave(); Framing.Leave(); Framing.Leave(); Framing.End();
            }
            public void Dispose()
            {
                try { Content?.Dispose(); }
                finally { Transform?.Dispose(); Aes?.Dispose(); }
            }
        }
        internal static Decryption OpenDecryption(Stream input, X509Certificate2Collection certificates, WebKey[] webKeys, SecretKey secret)
        {
            var framing = new BerStreamReader(input);
            framing.Enter(0x30); NativeStreamingCms.ExpectOid(framing.ReadEncoded(), CryptoEncoding.EnvelopedData);
            framing.Enter(0xA0); framing.Enter(0x30);
            var versionReader = new AsnReader(framing.ReadEncoded(), AsnEncodingRules.BER); versionReader.ReadInteger(); versionReader.ThrowIfNotEmpty();
            if (framing.PeekTag() == 0xA0) framing.ReadEncoded();
            var recipientsReader = new AsnReader(framing.ReadEncoded(), AsnEncodingRules.BER);
            var recipients = recipientsReader.ReadSetOf(true); recipientsReader.ThrowIfNotEmpty();
            framing.Enter(0x30); NativeStreamingCms.ExpectOid(framing.ReadEncoded(), CryptoEncoding.Data);
            var algorithmReader = new AsnReader(framing.ReadEncoded(), AsnEncodingRules.BER);
            var algorithm = CryptoEncoding.ReadAlgorithm(algorithmReader); algorithmReader.ThrowIfNotEmpty();
            int aesBits = algorithm.Oid switch { Aes128Cbc => 128, "2.16.840.1.101.3.4.1.22" => 192, "2.16.840.1.101.3.4.1.42" => 256, _ => throw new InvalidMessageException("Unsupported content encryption algorithm") };
            var ivReader = new AsnReader(algorithm.Parameters, AsnEncodingRules.DER); byte[] iv = ivReader.ReadOctetString(); ivReader.ThrowIfNotEmpty();
            byte[] key = null; var result = new Decryption();
            try
            {
                while (recipients.HasData)
                {
                    var encodedRecipient = recipients.ReadEncodedValue(); var reader = new AsnReader(encodedRecipient, AsnEncodingRules.BER);
                    if (reader.PeekTag().HasSameClassAndValue(CryptoEncoding.Context(2)))
                    {
                        var recipient = reader.ReadSequence(CryptoEncoding.Context(2)); if (recipient.ReadInteger() != 4) throw new InvalidMessageException("Invalid KEK version");
                        var identifier = recipient.ReadSequence(); byte[] id = identifier.ReadOctetString(); while (identifier.HasData) identifier.ReadEncodedValue();
                        var keyAlgorithm = CryptoEncoding.ReadAlgorithm(recipient); byte[] wrapped = recipient.ReadOctetString(); recipient.ThrowIfNotEmpty();
                        if (secret == null || !id.AsSpan().SequenceEqual(secret.Id)) continue;
                        if (keyAlgorithm.Oid != WrapOid(secret.NativeKey.Length)) throw new InvalidMessageException("Unexpected KEK wrapping algorithm");
                        using var wrap = Aes.Create(); wrap.Key = secret.NativeKey; key = EncryptedXml.DecryptKey(wrapped, wrap);
                        result.KeyId = id; result.KeyAlgorithm = keyAlgorithm.Oid; result.KeySize = secret.NativeKey.Length * 8; break;
                    }
                    if (!reader.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence)) continue;
                    if (secret != null) continue; // An explicit KEK must not silently fall back to another recipient identity.
                    var transport = reader.ReadSequence(); transport.ReadInteger(); byte[] ski = null, issuer = null; string serial = null;
                    if (transport.PeekTag().HasSameClassAndValue(CryptoEncoding.Context(0, false))) ski = transport.ReadOctetString(CryptoEncoding.Context(0, false));
                    else { var identity = transport.ReadSequence(); issuer = identity.ReadEncodedValue().ToArray(); serial = CryptoEncoding.SerialKey(identity.ReadIntegerBytes().Span); identity.ThrowIfNotEmpty(); }
                    var keyAlg = CryptoEncoding.ReadAlgorithm(transport); byte[] wrappedKey = transport.ReadOctetString(); transport.ThrowIfNotEmpty();
                    if (keyAlg.Oid != CryptoEncoding.Rsa) throw new InvalidMessageException("Unsupported RSA key transport algorithm");
                    var candidates = (certificates ?? new X509Certificate2Collection()).Cast<X509Certificate2>().Where(c => c.HasPrivateKey && (ski != null ? CryptoEncoding.SubjectKeyIdentifier(c).AsSpan().SequenceEqual(ski) : CryptoEncoding.SerialKey(CryptoEncoding.Serial(c)) == serial && CryptoEncoding.NamesEqual(c.IssuerName.RawData, issuer)))
                        .OrderByDescending(c => c.NotBefore).ToArray();
                    if (candidates.Length != 0)
                    {
                        using var rsa = candidates[0].GetRSAPrivateKey(); if (rsa == null) continue;
                        key = rsa.Decrypt(wrappedKey, RSAEncryptionPadding.Pkcs1); result.Candidates = candidates; result.KeyId = CryptoEncoding.SubjectKeyIdentifier(candidates[0]); result.KeySize = rsa.KeySize; result.KeyAlgorithm = keyAlg.Oid; break;
                    }
                    var web = (webKeys ?? Array.Empty<WebKey>()).FirstOrDefault(w => ski != null && w.Id.AsSpan().SequenceEqual(ski));
                    if (web?.NativeKey is RSA rsaWeb)
                    { lock (rsaWeb) key = rsaWeb.Decrypt(wrappedKey, RSAEncryptionPadding.Pkcs1); result.KeyId = ski; result.PublicKey = rsaWeb; result.KeyAlgorithm = keyAlg.Oid; result.KeySize = rsaWeb.KeySize; break; }
                }
                if (key == null) throw new InvalidMessageException("The message is not addressed to an available recipient");
                if (key.Length * 8 != aesBits || iv.Length != 16) throw new InvalidMessageException("Invalid AES parameters");
                OperationScope.Cancellation.ThrowIfCancellationRequested();
                result.Aes = Aes.Create(); result.Aes.Key = key; result.Aes.IV = iv;
                result.Transform = result.Aes.CreateDecryptor(); result.Framing = framing;
                result.Content = new CryptoStream(framing.OpenOctets(0x80), result.Transform, CryptoStreamMode.Read, true);
                return result;
            }
            catch { result.Dispose(); throw; }
            finally { if (key != null) CryptographicOperations.ZeroMemory(key); }
        }
    }
}
