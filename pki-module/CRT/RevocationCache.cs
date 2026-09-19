using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using BCAO = Org.BouncyCastle.Asn1.Ocsp;
using BCAX = Org.BouncyCastle.Asn1.X509;
using BCO = Org.BouncyCastle.Ocsp;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>
    /// Process wide cache of downloaded OCSP responses and CRLs, kept until their NextUpdate.
    /// </summary>
    public static class RevocationCache
    {
        private sealed class Entry<T>
        {
            public T Value { get; }
            public DateTime Expires { get; }

            public Entry(T value, DateTime expires)
            {
                Value = value;
                Expires = expires;
            }
        }

        private const int PurgeThreshold = 1024;

        private static readonly ConcurrentDictionary<string, Entry<BCAO.BasicOcspResponse>> ocsps = new ConcurrentDictionary<string, Entry<BCAO.BasicOcspResponse>>();
        private static readonly ConcurrentDictionary<string, Entry<BCAX.CertificateList>> crls = new ConcurrentDictionary<string, Entry<BCAX.CertificateList>>();

        /// <summary>
        /// Set to <c>false</c> to always download revocation information.
        /// </summary>
        public static bool Enabled { get; set; } = true;

        /// <summary>
        /// Lifetime of a cached entry when it does not carry a NextUpdate, defaults to 1 hour.
        /// </summary>
        public static TimeSpan DefaultLifetime { get; set; } = TimeSpan.FromHours(1);

        /// <summary>
        /// Remove all cached entries.
        /// </summary>
        public static void Clear()
        {
            ocsps.Clear();
            crls.Clear();
        }

        internal static bool TryGetOcsp(X509Certificate2 cert, X509Certificate2 issuer, out BCAO.BasicOcspResponse response)
        {
            return TryGet(ocsps, OcspKey(cert, issuer), out response);
        }

        internal static void PutOcsp(X509Certificate2 cert, X509Certificate2 issuer, BCAO.BasicOcspResponse response)
        {
            if (!Enabled) return;
            var parsed = new BCO.BasicOcspResp(response);
            DateTime expires = parsed.Responses
                .Select(r => r.NextUpdate)
                .Where(n => n != null)
                .Select(n => n.Value)
                .DefaultIfEmpty(parsed.ProducedAt + DefaultLifetime)
                .Min();
            Put(ocsps, OcspKey(cert, issuer), response, expires);
        }

        internal static bool TryGetCrl(X509Certificate2 cert, out BCAX.CertificateList crl)
        {
            return TryGet(crls, cert.Issuer, out crl);
        }

        internal static void PutCrl(X509Certificate2 cert, BCAX.CertificateList crl)
        {
            if (!Enabled) return;
            var parsed = ParsedCrl.Get(crl).Crl;
            DateTime expires = parsed.NextUpdate ?? parsed.ThisUpdate + DefaultLifetime;
            Put(crls, cert.Issuer, crl, expires);
        }

        private static string OcspKey(X509Certificate2 cert, X509Certificate2 issuer)
        {
            return issuer.Thumbprint + "|" + cert.SerialNumber;
        }

        private static bool TryGet<T>(ConcurrentDictionary<string, Entry<T>> store, string key, out T value)
        {
            value = default;
            if (!Enabled || !store.TryGetValue(key, out Entry<T> entry)) return false;
            if (entry.Expires <= DateTime.UtcNow)
            {
                store.TryRemove(key, out _);
                return false;
            }
            value = entry.Value;
            return true;
        }

        private static void Put<T>(ConcurrentDictionary<string, Entry<T>> store, string key, T value, DateTime expires)
        {
            if (expires <= DateTime.UtcNow) return;
            if (store.Count >= PurgeThreshold)
            {
                DateTime now = DateTime.UtcNow;
                foreach (var stale in store.Where(kv => kv.Value.Expires <= now).Select(kv => kv.Key).ToList())
                {
                    store.TryRemove(stale, out _);
                }
            }
            store[key] = new Entry<T>(value, expires);
        }
    }
}
