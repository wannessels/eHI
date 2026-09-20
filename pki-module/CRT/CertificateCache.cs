using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>Bounded cache of decoded certificates keyed by the thumbprint of their encoding; callers receive handle copies they own.</summary>
    public static class CertificateCache
    {
        private static readonly ConcurrentDictionary<string, X509Certificate2> entries = new ConcurrentDictionary<string, X509Certificate2>();
        /// <summary>Maximum number of retained certificates.</summary>
        public static int EntryLimit { get; set; } = 4096;
        /// <summary>Number of retained certificates.</summary>
        public static int Count => entries.Count;
        /// <summary>Removes retained certificates; copies already handed out stay valid.</summary>
        public static void Clear() => entries.Clear();
        /// <summary>Returns a caller-owned copy of the certificate with this DER encoding, decoding it only the first time.</summary>
        public static X509Certificate2 Load(ReadOnlySpan<byte> encoded)
        {
            string key = Convert.ToHexString(SHA1.HashData(encoded));
            if (!entries.TryGetValue(key, out var cached))
            {
                if (entries.Count >= EntryLimit) entries.Clear();
                var decoded = new X509Certificate2(encoded);
                cached = entries.GetOrAdd(key, decoded);
                if (!ReferenceEquals(cached, decoded)) decoded.Dispose();
            }
            return new X509Certificate2(cached);
        }
    }
}
