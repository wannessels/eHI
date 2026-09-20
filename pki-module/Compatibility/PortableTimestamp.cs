#if LEGACY_RUNTIME
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;

namespace Egelke.EHealth.Client.Pki.Compatibility
{
    /// <summary>RFC 3161 token support on runtimes that lack the platform token API.</summary>
    public sealed class PortableTimestampToken
    {
        private readonly TimeStampToken token;
        internal PortableTimestampToken(TimeStampToken token) { this.token = token; TokenInfo = new PortableTimestampTokenInfo(token.TimeStampInfo); }
        public PortableTimestampTokenInfo TokenInfo { get; }
        public PortableSignedCms AsSignedCms() { var cms = new PortableSignedCms(); cms.Decode(token.GetEncoded()); return cms; }
        public static bool TryDecode(ReadOnlyMemory<byte> encoded, out PortableTimestampToken result, out int consumed)
        {
            result = null; consumed = 0;
            try
            {
                byte[] value = encoded.ToArray(); Asn1Object.FromByteArray(value);
                result = new PortableTimestampToken(new TimeStampToken(new CmsSignedData(value))); consumed = value.Length; return true;
            }
            catch (Exception error) when (error is ArgumentException || error is IOException || error is CmsException || error is TspException) { return false; }
        }
        public bool VerifySignatureForHash(ReadOnlySpan<byte> hash, Oid algorithm, out X509Certificate2 signer, X509Certificate2Collection candidates)
        {
            signer = null;
            if (algorithm.Value != TokenInfo.HashAlgorithmId.Value || !RuntimeCompat.FixedTimeEquals(hash, TokenInfo.GetMessageHash().Span)) return false;
            foreach (X509Certificate2 candidate in candidates)
            {
                var cert = DotNetUtilities.FromX509Certificate(candidate);
                if (!token.SignerID.Match(cert)) continue;
                try
                {
                    // Validates the signature, ESS certificate binding, timestamping
                    // purpose and certificate validity at generation time.
                    token.Validate(cert); signer = candidate; return true;
                }
                catch (Exception error) when (error is TspException || error is ArgumentException || error is CryptographicException) { }
            }
            return false;
        }
    }
    public sealed class PortableTimestampTokenInfo
    {
        private readonly TimeStampTokenInfo information;
        internal PortableTimestampTokenInfo(TimeStampTokenInfo information) { this.information = information; }
        public Oid HashAlgorithmId => new Oid(information.MessageImprintAlgOid);
        public DateTimeOffset Timestamp => new DateTimeOffset(DateTime.SpecifyKind(information.GenTime, DateTimeKind.Utc));
        public ReadOnlyMemory<byte> GetMessageHash() => information.GetMessageImprintDigest();
    }
    public sealed class PortableTimestampRequest
    {
        private readonly TimeStampRequest request;
        private PortableTimestampRequest(TimeStampRequest request) { this.request = request; }
        public static PortableTimestampRequest CreateFromHash(ReadOnlySpan<byte> hash, HashAlgorithmName algorithm, bool requestSignerCertificates)
        {
            string oid = algorithm.Name == "SHA1" ? CryptoEncoding.Sha1 : algorithm.Name == "SHA256" ? CryptoEncoding.Sha256 :
                algorithm.Name == "SHA384" ? CryptoEncoding.Sha384 : algorithm.Name == "SHA512" ? CryptoEncoding.Sha512 : throw new CryptographicException("Unsupported timestamp hash");
            var generator = new TimeStampRequestGenerator(); generator.SetCertReq(requestSignerCertificates);
            return new PortableTimestampRequest(generator.Generate(oid, hash.ToArray()));
        }
        public byte[] Encode() => request.GetEncoded();
        public PortableTimestampToken ProcessResponse(byte[] encoded, out int consumed)
        {
            Asn1Object.FromByteArray(encoded); var response = new TimeStampResponse(encoded); response.Validate(request);
            if (response.TimeStampToken == null) throw new CryptographicException("Timestamp authority did not grant the request");
            var token = new PortableTimestampToken(response.TimeStampToken);
            var certificates = token.AsSignedCms().Certificates;
            try
            {
                if (!token.VerifySignatureForHash(token.TokenInfo.GetMessageHash().Span, token.TokenInfo.HashAlgorithmId, out _, certificates))
                    throw new CryptographicException("Invalid timestamp response signature");
            }
            finally { X509CertificateHelper.DisposeAll(certificates); }
            consumed = encoded.Length; return token;
        }
    }
}
#endif
