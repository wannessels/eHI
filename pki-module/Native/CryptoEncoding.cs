using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>Native ASN.1 and cryptographic operations used by the eHealth profiles.</summary>
    public static class CryptoEncoding
    {
        public const string Data = "1.2.840.113549.1.7.1";
        public const string SignedData = "1.2.840.113549.1.7.2";
        public const string EnvelopedData = "1.2.840.113549.1.7.3";
        public const string Sha1 = "1.3.14.3.2.26";
        public const string Sha256 = "2.16.840.1.101.3.4.2.1";
        public const string Sha384 = "2.16.840.1.101.3.4.2.2";
        public const string Sha512 = "2.16.840.1.101.3.4.2.3";
        public const string Rsa = "1.2.840.113549.1.1.1";
        public const string RsaPss = "1.2.840.113549.1.1.10";
        public const string TimestampAttribute = "1.2.840.113549.1.9.16.2.14";
        public const string RevocationAttribute = "1.2.840.113549.1.9.16.2.24";
        public static Asn1Tag Context(int value, bool constructed = true) => new Asn1Tag(TagClass.ContextSpecific, value, constructed);
        public static AsnReader Sequence(ReadOnlyMemory<byte> encoded, AsnEncodingRules rules = AsnEncodingRules.DER)
        {
            var reader = new AsnReader(encoded, rules);
            var sequence = reader.ReadSequence(); reader.ThrowIfNotEmpty(); return sequence;
        }
        public static DateTime ReadTime(AsnReader reader) => (reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime) ? reader.ReadUtcTime() : reader.ReadGeneralizedTime()).UtcDateTime;
        public static HashAlgorithmName HashName(string oid) => oid switch
        {
            Sha1 => HashAlgorithmName.SHA1,
            Sha256 => HashAlgorithmName.SHA256,
            Sha384 => HashAlgorithmName.SHA384,
            Sha512 => HashAlgorithmName.SHA512,
            _ => throw new CryptographicException("Unsupported digest algorithm: " + oid)
        };
        public static byte[] Hash(string oid, ReadOnlySpan<byte> bytes) { using var hash = IncrementalHash.CreateHash(HashName(oid)); hash.AppendData(bytes); return hash.GetHashAndReset(); }
        public static byte[] SubjectKeyIdentifier(X509Certificate2 cert)
        {
            var ski = cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().SingleOrDefault();
            return ski == null ? SHA1.HashData(cert.PublicKey.EncodedKeyValue.RawData) : Convert.FromHexString(ski.SubjectKeyIdentifier);
        }
        public static byte[] Serial(X509Certificate2 cert) => cert.GetSerialNumber().Reverse().SkipWhile(b => b == 0).DefaultIfEmpty((byte)0).ToArray();
        public static string SerialKey(ReadOnlySpan<byte> serial)
        {
            int offset = 0; while (offset < serial.Length - 1 && serial[offset] == 0) offset++;
            return Convert.ToHexString(serial.Slice(offset));
        }
        public static string ReadSerial(AsnReader reader)
        {
            var value = reader.ReadIntegerBytes();
            if (value.IsEmpty || (value.Span[0] & 128) != 0) throw new CryptographicException("Negative certificate serial number");
            return SerialKey(value.Span);
        }
        public static bool ValidAt(X509Certificate2 cert, DateTime time) => cert.NotBefore.ToUniversalTime() <= time.ToUniversalTime() && cert.NotAfter.ToUniversalTime() >= time.ToUniversalTime();
        public static bool HasKeyUsage(X509Certificate2 cert, int bit)
        {
            var usage = cert.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
            int[] flags = { 128, 64, 32, 16, 8, 4, 2, 1, 32768 };
            return usage != null && bit >= 0 && bit < flags.Length && ((int)usage.KeyUsages & flags[bit]) != 0;
        }
        public static bool HasPurpose(X509Certificate2 cert, string purpose) => cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(e => e.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == purpose));
        public static bool NamesEqual(byte[] first, byte[] second) => first.AsSpan().SequenceEqual(second) || CanonicalName(first).SequenceEqual(CanonicalName(second));
        public static string FormatDistinguishedNameRfc1779(X500DistinguishedName name)
        {
            var symbols = new Dictionary<string, string> { ["2.5.4.6"] = "C", ["2.5.4.10"] = "O", ["2.5.4.11"] = "OU", ["2.5.4.3"] = "CN", ["2.5.4.7"] = "L", ["2.5.4.8"] = "ST", ["2.5.4.9"] = "STREET" };
            var rdns = new List<string>(); var reader = Sequence(name.RawData);
            while (reader.HasData)
            {
                var set = reader.ReadSetOf(); var attributes = new List<string>();
                while (set.HasData)
                {
                    var attribute = set.ReadSequence(); string oid = attribute.ReadObjectIdentifier();
                    string text = attribute.ReadCharacterString((UniversalTagNumber)attribute.PeekTag().TagValue);
                    var escaped = new StringBuilder();
                    int leading = 0, trailing = text.Length;
                    while (leading < text.Length && text[leading] == ' ') leading++;
                    while (trailing > 0 && text[trailing - 1] == ' ') trailing--;
                    for (int index = 0; index < text.Length; index++)
                    {
                        char value = text[index];
                        if (",+\"\\<>;=".IndexOf(value) >= 0 || value == '#' && index == 0 || value == ' ' && (index < leading || index >= trailing)) escaped.Append('\\');
                        escaped.Append(value);
                    }
                    attribute.ThrowIfNotEmpty(); attributes.Add((symbols.TryGetValue(oid, out var symbol) ? symbol : oid) + "=" + escaped);
                }
                rdns.Add(string.Join("+", attributes));
            }
            rdns.Reverse(); return string.Join(",", rdns);
        }
        private static IEnumerable<string> CanonicalName(byte[] encoded)
        {
            var name = Sequence(encoded);
            while (name.HasData)
            {
                var set = name.ReadSetOf(); var attributes = new List<string>();
                while (set.HasData)
                {
                    var pair = set.ReadSequence(); string oid = pair.ReadObjectIdentifier();
                    string value = pair.ReadCharacterString((UniversalTagNumber)pair.PeekTag().TagValue);
                    pair.ThrowIfNotEmpty();
                    attributes.Add(oid + "=" + string.Join(" ", value.Normalize(NormalizationForm.FormKC).Split((char[])null, StringSplitOptions.RemoveEmptyEntries)).ToUpperInvariant());
                }
                yield return string.Join("+", attributes.OrderBy(v => v, StringComparer.Ordinal));
            }
        }
        public static string[] NameValues(X500DistinguishedName name, string oid)
        {
            var values = new List<string>(); var reader = Sequence(name.RawData);
            while (reader.HasData)
            {
                var set = reader.ReadSetOf(); while (set.HasData)
                {
                    var pair = set.ReadSequence(); string type = pair.ReadObjectIdentifier();
                    if (type == oid) values.Add(pair.ReadCharacterString((UniversalTagNumber)pair.PeekTag().TagValue));
                }
            }
            return values.ToArray();
        }
        public static (string Oid, byte[] Parameters) ReadAlgorithm(AsnReader parent)
        {
            var algorithm = parent.ReadSequence(); string oid = algorithm.ReadObjectIdentifier();
            byte[] parameters = algorithm.HasData ? algorithm.ReadEncodedValue().ToArray() : null;
            algorithm.ThrowIfNotEmpty(); return (oid, parameters);
        }
        public static void WriteAlgorithm(AsnWriter writer, string oid, bool includeNull = true)
        {
            using (writer.PushSequence()) { writer.WriteObjectIdentifier(oid); if (includeNull) writer.WriteNull(); }
        }
        public static bool VerifySignature(X509Certificate2 signer, ReadOnlySpan<byte> data, string oid, byte[] parameters, ReadOnlySpan<byte> signature)
        {
            if (oid != RsaPss && parameters != null && !parameters.AsSpan().SequenceEqual(new byte[] { 5, 0 }))
                throw new CryptographicException("Unsupported signature parameters");
            string digest = oid switch
            {
                "1.2.840.113549.1.1.5" or "1.2.840.10040.4.3" => Sha1,
                "1.2.840.113549.1.1.11" or "1.2.840.10045.4.3.2" or "2.16.840.1.101.3.4.3.2" => Sha256,
                "1.2.840.113549.1.1.12" or "1.2.840.10045.4.3.3" => Sha384,
                "1.2.840.113549.1.1.13" or "1.2.840.10045.4.3.4" => Sha512,
                RsaPss => ReadPssDigest(parameters),
                _ => throw new CryptographicException("Unsupported signature algorithm: " + oid)
            };
            if (oid.StartsWith("1.2.840.113549.1.1.", StringComparison.Ordinal))
            { using var key = signer.GetRSAPublicKey(); return key != null && key.VerifyData(data, signature, HashName(digest), oid == RsaPss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1); }
            if (oid.StartsWith("1.2.840.10045.", StringComparison.Ordinal))
            { using var key = signer.GetECDsaPublicKey(); return key != null && key.VerifyData(data, signature, HashName(digest), DSASignatureFormat.Rfc3279DerSequence); }
            using (var key = signer.GetDSAPublicKey()) return key != null && key.VerifyData(data, signature, HashName(digest), DSASignatureFormat.Rfc3279DerSequence);
        }
        /// <summary>Validates the platform-supported RSA-PSS parameter profile and returns its digest OID.</summary>
        public static string ReadPssDigest(byte[] parameters)
        {
            string hash = Sha1, mgfHash = Sha1; int salt = 20, trailer = 1;
            if (parameters != null)
            {
                var pss = Sequence(parameters);
                if (pss.HasData && pss.PeekTag().HasSameClassAndValue(Context(0))) { var item = pss.ReadSequence(Context(0)); hash = ReadAlgorithm(item).Oid; item.ThrowIfNotEmpty(); }
                if (pss.HasData && pss.PeekTag().HasSameClassAndValue(Context(1)))
                { var item = pss.ReadSequence(Context(1)); var mgf = ReadAlgorithm(item); item.ThrowIfNotEmpty(); if (mgf.Oid != "1.2.840.113549.1.1.8") throw new CryptographicException("Unsupported PSS mask function"); mgfHash = ReadAlgorithm(new AsnReader(mgf.Parameters, AsnEncodingRules.DER)).Oid; }
                if (pss.HasData && pss.PeekTag().HasSameClassAndValue(Context(2))) { var item = pss.ReadSequence(Context(2)); salt = (int)item.ReadInteger(); item.ThrowIfNotEmpty(); }
                if (pss.HasData && pss.PeekTag().HasSameClassAndValue(Context(3))) { var item = pss.ReadSequence(Context(3)); trailer = (int)item.ReadInteger(); item.ThrowIfNotEmpty(); }
                pss.ThrowIfNotEmpty();
            }
            if (mgfHash != hash || salt != Hash(hash, ReadOnlySpan<byte>.Empty).Length || trailer != 1) throw new CryptographicException("Unsupported PSS parameters");
            return hash;
        }
        public static bool VerifyCertificate(X509Certificate2 cert, X509Certificate2 issuer)
        {
            var value = Sequence(cert.RawData); var tbs = value.ReadEncodedValue(); var algorithm = ReadAlgorithm(value);
            byte[] signature = value.ReadBitString(out int unused); value.ThrowIfNotEmpty();
            if (unused != 0) return false;
            var body = Sequence(tbs);
            if (body.PeekTag().HasSameClassAndValue(Context(0))) body.ReadEncodedValue();
            body.ReadIntegerBytes(); var innerAlgorithm = ReadAlgorithm(body);
            if (innerAlgorithm.Oid != algorithm.Oid) return false;
            if (algorithm.Oid == RsaPss && !((innerAlgorithm.Parameters ?? Array.Empty<byte>()).AsSpan().SequenceEqual(algorithm.Parameters ?? Array.Empty<byte>()))) return false;
            return VerifySignature(issuer, tbs.Span, algorithm.Oid, algorithm.Parameters, signature);
        }
        public static Dictionary<string, (bool Critical, byte[] Value)> ReadExtensions(AsnReader parent)
        {
            var result = new Dictionary<string, (bool, byte[])>(); var extensions = parent.ReadSequence();
            while (extensions.HasData)
            {
                var item = extensions.ReadSequence(); var oid = item.ReadObjectIdentifier();
                bool critical = item.HasData && item.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean) && item.ReadBoolean();
                var value = item.ReadOctetString(); item.ThrowIfNotEmpty();
                if (!result.TryAdd(oid, (critical, value))) throw new CryptographicException("Duplicate extension");
            }
            return result;
        }
    }
}
