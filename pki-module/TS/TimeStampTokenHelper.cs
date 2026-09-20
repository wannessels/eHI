using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>RFC 3161 parsing and validation using platform PKCS APIs.</summary>
    public static class TimeStampTokenHelper
    {
        public static Rfc3161TimestampToken ToTimeStampToken(this byte[] bytes)
        {
            if (!Rfc3161TimestampToken.TryDecode(bytes, out var token, out int consumed) || consumed != bytes.Length)
                throw new CryptographicException("Invalid RFC 3161 timestamp token");
            var information = CryptoEncoding.Sequence(token.AsSignedCms().ContentInfo.Content);
            information.ReadInteger(); information.ReadObjectIdentifier();
            var imprint = information.ReadSequence(); var digest = CryptoEncoding.ReadAlgorithm(imprint);
            if (digest.Parameters != null && !digest.Parameters.AsSpan().SequenceEqual(new byte[] { 5, 0 }))
                throw new CryptographicException("Unsupported timestamp hash parameters");
            return token;
        }
        public static byte[] GetEncoded(this Rfc3161TimestampToken token) => token.AsSignedCms().Encode();
        public static bool IsMatch(this Rfc3161TimestampToken token, Stream data)
        {
            using var hash = IncrementalHash.CreateHash(CryptoEncoding.HashName(token.TokenInfo.HashAlgorithmId.Value));
            var buffer = new byte[81920]; int count;
            while ((count = data.Read(buffer, 0, buffer.Length)) != 0) { OperationScope.Cancellation.ThrowIfCancellationRequested(); hash.AppendData(buffer, 0, count); }
            return CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), token.TokenInfo.GetMessageHash().Span);
        }
        public static Timestamp Validate(this Rfc3161TimestampToken token) => token.ValidateAsync().GetAwaiter().GetResult();
        public static Timestamp Validate(this Rfc3161TimestampToken token, X509Certificate2Collection extra) => token.ValidateAsync(extra).GetAwaiter().GetResult();
        public static Timestamp Validate(this Rfc3161TimestampToken token, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps) => token.ValidateAsync(crls, ocsps).GetAwaiter().GetResult();
        public static Timestamp Validate(this Rfc3161TimestampToken token, X509Certificate2Collection extra, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps) => token.ValidateAsync(extra, crls, ocsps, null).GetAwaiter().GetResult();
        public static Timestamp Validate(this Rfc3161TimestampToken token, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps, DateTime? time) => token.ValidateAsync(null, crls, ocsps, time).GetAwaiter().GetResult();
        public static Timestamp Validate(this Rfc3161TimestampToken token, X509Certificate2Collection extra, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps, DateTime? time) => token.ValidateAsync(extra, crls, ocsps, time).GetAwaiter().GetResult();
        public static Task<Timestamp> ValidateAsync(this Rfc3161TimestampToken token) => token.ValidateAsync(null, new List<CertificateRevocationList>(), new List<OcspResponse>(), null);
        public static Task<Timestamp> ValidateAsync(this Rfc3161TimestampToken token, X509Certificate2Collection extra) => token.ValidateAsync(extra, new List<CertificateRevocationList>(), new List<OcspResponse>(), null);
        public static Task<Timestamp> ValidateAsync(this Rfc3161TimestampToken token, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps) => token.ValidateAsync(null, crls, ocsps, null);
        public static Task<Timestamp> ValidateAsync(this Rfc3161TimestampToken token, X509Certificate2Collection extra, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps) => token.ValidateAsync(extra, crls, ocsps, null);
        public static Task<Timestamp> ValidateAsync(this Rfc3161TimestampToken token, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps, DateTime? time) => token.ValidateAsync(null, crls, ocsps, time);
        public static async Task<Timestamp> ValidateAsync(this Rfc3161TimestampToken token, X509Certificate2Collection extra, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps, DateTime? time)
        {
            var result = new Timestamp { Time = token.TokenInfo.Timestamp.UtcDateTime, TimestampStatus = new List<X509ChainStatus>(), CertificateChain = new Chain() };
            var certificates = token.AsSignedCms().Certificates;
            var candidates = new X509Certificate2Collection(certificates);
            if (extra != null) candidates.AddRange(extra);
            try
            {
                if (!token.VerifySignatureForHash(token.TokenInfo.GetMessageHash().Span, token.TokenInfo.HashAlgorithmId, out var signer, candidates))
                {
                    result.TimestampStatus.Add(new X509ChainStatus { Status = X509ChainStatusFlags.NotSignatureValid, StatusInformation = "Invalid timestamp signature, signing-certificate binding, or timestamping purpose" });
                    return result;
                }
                result.CertificateChain = await signer.BuildChainAsync(time ?? result.Time, candidates, crls, ocsps).ConfigureAwait(false);
                result.RenewalTime = result.CertificateChain.GetMinNotAfter();
                result.TimestampStatus.AddRange(result.CertificateChain.ChainStatus);
                return result;
            }
            finally { foreach (var cert in certificates) cert.Dispose(); }
        }
    }
}
