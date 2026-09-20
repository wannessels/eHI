using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>Bounded cache of certificate public keys keyed by thumbprint; the returned keys are shared and must not be disposed.</summary>
    public static class PublicKeyCache
    {
        private static readonly ConcurrentDictionary<string, AsymmetricAlgorithm> entries = new ConcurrentDictionary<string, AsymmetricAlgorithm>();
        /// <summary>Maximum number of retained keys.</summary>
        public static int EntryLimit { get; set; } = 4096;
        /// <summary>Number of retained keys.</summary>
        public static int Count => entries.Count;
        /// <summary>Removes retained keys; keys already in use stay valid.</summary>
        public static void Clear() => entries.Clear();
        /// <summary>The certificate's RSA, ECDSA or DSA public key, or null for other algorithms.</summary>
        public static AsymmetricAlgorithm Get(X509Certificate2 certificate)
        {
            string key = certificate.Thumbprint;
            if (entries.TryGetValue(key, out var cached)) return cached;
            var created = (AsymmetricAlgorithm)certificate.GetRSAPublicKey() ?? certificate.GetECDsaPublicKey() ?? (AsymmetricAlgorithm)RuntimeCompat.GetDsaPublicKey(certificate);
            if (created == null) return null;
            if (entries.Count >= EntryLimit) entries.Clear();
            cached = entries.GetOrAdd(key, created);
            if (!ReferenceEquals(cached, created)) created.Dispose();
            return cached;
        }
    }
}
