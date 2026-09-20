using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>An immutable DER certificate revocation list, verified with platform cryptography.</summary>
    public sealed class CertificateRevocationList
    {
        private readonly byte[] encoded, issuer, signature;
        private readonly ReadOnlyMemory<byte> signed;
        private readonly (string Oid, byte[] Parameters) algorithm;
        private readonly Dictionary<string, DateTime> revoked = new Dictionary<string, DateTime>();
        private readonly Dictionary<string, (bool Critical, byte[] Value)> extensions;
        private readonly object sync = new object();
        private string verifiedIssuer;
        public DateTime ThisUpdate { get; }
        public DateTime? NextUpdate { get; }
        public byte[] GetEncoded() => (byte[])encoded.Clone();
        internal int EncodedLength => encoded.Length;
        // The encoded list plus the parsed serial dictionary; a 350k-entry Citizen CA list is charged about 57 MiB.
        internal long EstimatedSize => encoded.Length + revoked.Count * 128L + 1024;
        public static CertificateRevocationList Parse(byte[] value) => new CertificateRevocationList(value);
        private CertificateRevocationList(byte[] value)
        {
            encoded = (byte[])value.Clone();
            var root = CryptoEncoding.Sequence(encoded); signed = root.ReadEncodedValue(); algorithm = CryptoEncoding.ReadAlgorithm(root);
            signature = root.ReadBitString(out int unused); root.ThrowIfNotEmpty();
            if (unused != 0) throw new CryptographicException("Invalid CRL signature encoding");
            var tbs = CryptoEncoding.Sequence(signed);
            if (tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Integer) && tbs.ReadInteger() != 1) throw new CryptographicException("Unsupported CRL version");
            var innerAlgorithm = CryptoEncoding.ReadAlgorithm(tbs);
            if (innerAlgorithm.Oid != algorithm.Oid) throw new CryptographicException("CRL signature algorithms disagree");
            issuer = tbs.ReadEncodedValue().ToArray();
            ThisUpdate = CryptoEncoding.ReadTime(tbs);
            if (tbs.HasData && (tbs.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime) || tbs.PeekTag().HasSameClassAndValue(Asn1Tag.GeneralizedTime))) NextUpdate = CryptoEncoding.ReadTime(tbs);
            if (NextUpdate < ThisUpdate) throw new CryptographicException("Invalid CRL validity interval");
            if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
            {
                var entries = tbs.ReadSequence();
                while (entries.HasData)
                {
                    var entry = entries.ReadSequence(); string serial = CryptoEncoding.ReadSerial(entry);
                    DateTime time = CryptoEncoding.ReadTime(entry);
                    if (!revoked.TryAdd(serial, time)) throw new CryptographicException("Duplicate CRL serial number");
                    if (entry.HasData)
                    {
                        var entryExtensions = CryptoEncoding.ReadExtensions(entry);
                        if (entryExtensions.Any(e => e.Value.Critical) || entryExtensions.ContainsKey("2.5.29.29")) throw new CryptographicException("Unsupported CRL entry extension");
                    }
                    entry.ThrowIfNotEmpty();
                }
            }
            extensions = new Dictionary<string, (bool, byte[])>();
            if (tbs.HasData)
            {
                var tagged = tbs.ReadSequence(CryptoEncoding.Context(0)); extensions = CryptoEncoding.ReadExtensions(tagged); tagged.ThrowIfNotEmpty();
            }
            tbs.ThrowIfNotEmpty();
            if (extensions.Any(e => e.Value.Critical && e.Key != "2.5.29.28")) throw new CryptographicException("Unsupported critical CRL extension");
        }
        internal bool Covers(X509Certificate2 cert, X509Certificate2 authority)
        {
            if (!CryptoEncoding.NamesEqual(issuer, authority.SubjectName.RawData) || !CryptoEncoding.NamesEqual(issuer, cert.IssuerName.RawData)) return false;
            if (extensions.ContainsKey("2.5.29.27")) return false; // Delta CRLs cannot establish a complete status alone.
            if (!extensions.TryGetValue("2.5.29.28", out var extension)) return true;
            var scope = CryptoEncoding.Sequence(extension.Value);
            HashSet<string> names = null;
            bool userOnly = false, caOnly = false;
            while (scope.HasData)
            {
                int tag = scope.PeekTag().TagValue;
                switch (tag)
                {
                    case 0: var point = scope.ReadSequence(CryptoEncoding.Context(0)); names = ReadDistributionPoint(point); point.ThrowIfNotEmpty(); break;
                    case 1: userOnly = scope.ReadBoolean(CryptoEncoding.Context(1, false)); break;
                    case 2: caOnly = scope.ReadBoolean(CryptoEncoding.Context(2, false)); break;
                    case 3: return false;
                    case 4: if (scope.ReadBoolean(CryptoEncoding.Context(4, false))) return false; break;
                    case 5: if (scope.ReadBoolean(CryptoEncoding.Context(5, false))) return false; break;
                    default: return false;
                }
            }
            bool ca = cert.Extensions.OfType<X509BasicConstraintsExtension>().Any(e => e.CertificateAuthority);
            if (userOnly && ca || caOnly && !ca) return false;
            return names == null || DistributionPoints(cert).Any(point => point.Overlaps(names));
        }
        internal void Verify(X509Certificate2 authority)
        {
            if (!CryptoEncoding.HasKeyUsage(authority, 6)) throw new RevocationUnknownException("Issuer cannot sign CRLs");
            lock (sync)
            {
                if (verifiedIssuer == authority.Thumbprint) return;
                if (!CryptoEncoding.VerifySignature(authority, signed.Span, algorithm.Oid, algorithm.Parameters, signature)) throw new RevocationUnknownException("Invalid CRL signature");
                verifiedIssuer = authority.Thumbprint;
            }
        }
        internal DateTime? RevocationTime(X509Certificate2 cert) => revoked.TryGetValue(CryptoEncoding.SerialKey(CryptoEncoding.Serial(cert)), out var time) ? time : null;
        internal static IEnumerable<HashSet<string>> DistributionPoints(X509Certificate2 cert)
        {
            var ext = cert.Extensions["2.5.29.31"]; if (ext == null) yield break;
            var points = CryptoEncoding.Sequence(ext.RawData);
            while (points.HasData)
            {
                var point = points.ReadSequence(); HashSet<string> names = null; bool scoped = false;
                while (point.HasData)
                {
                    int tag = point.PeekTag().TagValue;
                    if (tag == 0) { var wrapper = point.ReadSequence(CryptoEncoding.Context(0)); names = ReadDistributionPoint(wrapper); wrapper.ThrowIfNotEmpty(); }
                    else { point.ReadEncodedValue(); scoped = true; }
                }
                if (names != null && !scoped) yield return names;
            }
        }
        private static HashSet<string> ReadDistributionPoint(AsnReader reader)
        {
            var result = new HashSet<string>(StringComparer.Ordinal);
            if (!reader.PeekTag().HasSameClassAndValue(CryptoEncoding.Context(0))) { reader.ReadEncodedValue(); return result; }
            var names = reader.ReadSequence(CryptoEncoding.Context(0));
            while (names.HasData)
            {
                if (names.PeekTag().HasSameClassAndValue(CryptoEncoding.Context(6, false))) result.Add(names.ReadCharacterString(UniversalTagNumber.IA5String, CryptoEncoding.Context(6, false)));
                else result.Add("der:" + Convert.ToHexString(names.ReadEncodedValue().Span));
            }
            return result;
        }
        internal static IEnumerable<Uri> DownloadUris(X509Certificate2 cert) => DistributionPoints(cert).SelectMany(p => p).Select(s => Uri.TryCreate(s, UriKind.Absolute, out var uri) ? uri : null).Where(uri => uri != null && (uri.Scheme == "http" || uri.Scheme == "https"));
    }

    /// <summary>An immutable successful BasicOCSPResponse (RFC 6960).</summary>
    public sealed class OcspResponse
    {
        public sealed class CertificateStatus
        {
            internal string HashOid, Serial;
            internal byte[] IssuerNameHash, IssuerKeyHash;
            internal int Status;
            public DateTime ThisUpdate { get; internal set; }
            public DateTime? NextUpdate { get; internal set; }
            public DateTime? RevocationTime { get; internal set; }
        }
        private readonly byte[] encoded, signed, signature, responderName, responderKeyHash;
        private readonly (string Oid, byte[] Parameters) algorithm;
        private readonly byte[][] certificates;
        private readonly object sync = new object();
        private string verifiedIssuer;
        public DateTime ProducedAt { get; }
        public IReadOnlyList<CertificateStatus> Responses { get; }
        public byte[] GetEncoded() => (byte[])encoded.Clone();
        internal int EncodedLength => encoded.Length;
        public static OcspResponse Parse(byte[] value)
        {
            var root = CryptoEncoding.Sequence(value);
            if (root.PeekTag().HasSameClassAndValue(Asn1Tag.Enumerated))
            {
                var status = root.ReadEnumeratedValue<ResponseStatus>();
                if (status != ResponseStatus.Successful) throw new RevocationUnknownException("OCSP responder status: " + status);
                var wrapper = root.ReadSequence(CryptoEncoding.Context(0)); var bytes = wrapper.ReadSequence();
                if (bytes.ReadObjectIdentifier() != "1.3.6.1.5.5.7.48.1.1") throw new RevocationUnknownException("Unsupported OCSP response type");
                value = bytes.ReadOctetString(); bytes.ThrowIfNotEmpty(); wrapper.ThrowIfNotEmpty(); root.ThrowIfNotEmpty();
            }
            return new OcspResponse(value);
        }
        private enum ResponseStatus { Successful = 0, Malformed = 1, InternalError = 2, TryLater = 3, SignatureRequired = 5, Unauthorized = 6 }
        private OcspResponse(byte[] value)
        {
            encoded = (byte[])value.Clone(); var root = CryptoEncoding.Sequence(encoded);
            signed = root.ReadEncodedValue().ToArray(); algorithm = CryptoEncoding.ReadAlgorithm(root);
            signature = root.ReadBitString(out int unused); if (unused != 0) throw new CryptographicException("Invalid OCSP signature encoding");
            var certs = new List<byte[]>();
            if (root.HasData) { var wrapper = root.ReadSequence(CryptoEncoding.Context(0)); var list = wrapper.ReadSequence(); while (list.HasData) certs.Add(list.ReadEncodedValue().ToArray()); wrapper.ThrowIfNotEmpty(); }
            root.ThrowIfNotEmpty(); certificates = certs.ToArray();
            var tbs = CryptoEncoding.Sequence(signed);
            if (tbs.PeekTag().HasSameClassAndValue(CryptoEncoding.Context(0))) { var version = tbs.ReadSequence(CryptoEncoding.Context(0)); if (version.ReadInteger() != 0) throw new CryptographicException("Unsupported OCSP version"); version.ThrowIfNotEmpty(); }
            if (tbs.PeekTag().HasSameClassAndValue(CryptoEncoding.Context(1))) { var name = tbs.ReadSequence(CryptoEncoding.Context(1)); responderName = name.ReadEncodedValue().ToArray(); name.ThrowIfNotEmpty(); }
            else { var key = tbs.ReadSequence(CryptoEncoding.Context(2)); responderKeyHash = key.ReadOctetString(); key.ThrowIfNotEmpty(); }
            ProducedAt = tbs.ReadGeneralizedTime().UtcDateTime;
            var statuses = new List<CertificateStatus>(); var identities = new HashSet<string>(); var responses = tbs.ReadSequence();
            while (responses.HasData)
            {
                var response = responses.ReadSequence(); var id = response.ReadSequence();
                var status = new CertificateStatus { HashOid = CryptoEncoding.ReadAlgorithm(id).Oid, IssuerNameHash = id.ReadOctetString(), IssuerKeyHash = id.ReadOctetString(), Serial = CryptoEncoding.ReadSerial(id) };
                if (!identities.Add(status.HashOid + "|" + Convert.ToHexString(status.IssuerNameHash) + "|" + Convert.ToHexString(status.IssuerKeyHash) + "|" + status.Serial)) throw new CryptographicException("Duplicate OCSP certificate status");
                id.ThrowIfNotEmpty(); status.Status = response.PeekTag().TagValue;
                if (status.Status == 1)
                {
                    var revocation = response.ReadSequence(CryptoEncoding.Context(1)); status.RevocationTime = revocation.ReadGeneralizedTime().UtcDateTime;
                    if (revocation.HasData) { var reason = revocation.ReadSequence(CryptoEncoding.Context(0)); reason.ReadEnumeratedBytes(); reason.ThrowIfNotEmpty(); }
                    revocation.ThrowIfNotEmpty();
                }
                else if (status.Status == 0 || status.Status == 2) response.ReadNull(CryptoEncoding.Context(status.Status, false));
                else throw new CryptographicException("Invalid OCSP status");
                status.ThisUpdate = response.ReadGeneralizedTime().UtcDateTime;
                if (response.HasData && response.PeekTag().HasSameClassAndValue(CryptoEncoding.Context(0))) { var next = response.ReadSequence(CryptoEncoding.Context(0)); status.NextUpdate = next.ReadGeneralizedTime().UtcDateTime; next.ThrowIfNotEmpty(); }
                if (status.NextUpdate < status.ThisUpdate) throw new CryptographicException("Invalid OCSP validity interval");
                if (response.HasData) ReadNonCriticalExtensions(response, 1);
                response.ThrowIfNotEmpty(); statuses.Add(status);
            }
            if (statuses.Count == 0) throw new CryptographicException("OCSP response has no certificate statuses");
            if (tbs.HasData) ReadNonCriticalExtensions(tbs, 1); tbs.ThrowIfNotEmpty(); Responses = statuses.AsReadOnly();
        }
        private static void ReadNonCriticalExtensions(AsnReader reader, int tag)
        {
            var wrapper = reader.ReadSequence(CryptoEncoding.Context(tag)); var extensions = CryptoEncoding.ReadExtensions(wrapper); wrapper.ThrowIfNotEmpty();
            if (extensions.Any(e => e.Value.Critical)) throw new CryptographicException("Unsupported critical OCSP extension");
        }
        internal CertificateStatus Match(X509Certificate2 cert, X509Certificate2 issuer, DateTime time, TimeSpan skew)
        {
            return Responses.Where(r => r.Serial == CryptoEncoding.SerialKey(CryptoEncoding.Serial(cert)) &&
                CryptographicOperations.FixedTimeEquals(r.IssuerNameHash, CryptoEncoding.Hash(r.HashOid, issuer.SubjectName.RawData)) &&
                CryptographicOperations.FixedTimeEquals(r.IssuerKeyHash, CryptoEncoding.Hash(r.HashOid, issuer.PublicKey.EncodedKeyValue.RawData)) &&
                r.ThisUpdate <= DateTime.UtcNow + skew && (r.ThisUpdate >= time - skew || r.NextUpdate >= time - skew)).OrderByDescending(r => r.ThisUpdate).FirstOrDefault();
        }
        internal void Verify(X509Certificate2 issuer)
        {
            if (ProducedAt > DateTime.UtcNow.AddMinutes(5)) throw new RevocationUnknownException("OCSP response was produced in the future");
            lock (sync)
            {
                if (verifiedIssuer == issuer.Thumbprint) return;
                if (!SignedByAuthorizedResponder(issuer)) throw new RevocationUnknownException("OCSP signature or responder authorization is invalid");
                verifiedIssuer = issuer.Thumbprint;
            }
        }
        private bool SignedByAuthorizedResponder(X509Certificate2 issuer)
        {
            var candidates = new List<X509Certificate2> { issuer };
            try
            {
                candidates.AddRange(certificates.Select(c => new X509Certificate2(c)));
                foreach (var candidate in candidates)
                {
                    bool matches = responderName != null ? CryptoEncoding.NamesEqual(responderName, candidate.SubjectName.RawData) : CryptographicOperations.FixedTimeEquals(responderKeyHash, SHA1.HashData(candidate.PublicKey.EncodedKeyValue.RawData));
                    if (!matches) continue;
                    bool directIssuer = candidate.RawData.AsSpan().SequenceEqual(issuer.RawData);
                    if (!directIssuer && (!CryptoEncoding.NamesEqual(candidate.IssuerName.RawData, issuer.SubjectName.RawData) || !CryptoEncoding.VerifyCertificate(candidate, issuer) || !CryptoEncoding.HasPurpose(candidate, "1.3.6.1.5.5.7.3.9"))) continue;
                    if (!CryptoEncoding.ValidAt(candidate, ProducedAt)) continue;
                    if (CryptoEncoding.VerifySignature(candidate, signed, algorithm.Oid, algorithm.Parameters, signature)) return true;
                }
                return false;
            }
            finally { foreach (var cert in candidates.Skip(1)) cert.Dispose(); }
        }
    }
}
