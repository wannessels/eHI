using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>Bounded process-wide cache of validated revocation evidence, retained until NextUpdate.</summary>
    public static class RevocationCache
    {
        private sealed class Entry
        {
            internal string Key;
            internal object Value;
            internal DateTime Expires;
            internal long Size;
        }
        private static readonly object sync = new object();
        private static readonly Dictionary<string, LinkedListNode<Entry>> entries = new Dictionary<string, LinkedListNode<Entry>>();
        private static readonly LinkedList<Entry> lru = new LinkedList<Entry>();
        private static long size;
        private static int entryLimit = 1024;
        private static long sizeLimitBytes = 256L * 1024 * 1024;

        /// <summary>Whether downloaded evidence is cached.</summary>
        public static bool Enabled { get; set; } = true;
        /// <summary>Lifetime when NextUpdate is absent.</summary>
        public static TimeSpan DefaultLifetime { get; set; } = TimeSpan.FromHours(1);
        /// <summary>Maximum number of retained entries.</summary>
        public static int EntryLimit
        {
            get { lock (sync) return entryLimit; }
            set { if (value < 1) throw new ArgumentOutOfRangeException(nameof(value)); lock (sync) { entryLimit = value; Trim(); } }
        }
        /// <summary>Budget for estimated retained memory including parsed CRLs. Excludes in-flight downloads.</summary>
        public static long SizeLimitBytes
        {
            get { lock (sync) return sizeLimitBytes; }
            set { if (value < 1) throw new ArgumentOutOfRangeException(nameof(value)); lock (sync) { sizeLimitBytes = value; Trim(); } }
        }
        /// <summary>Number of retained entries.</summary>
        public static int Count { get { lock (sync) return entries.Count; } }
        /// <summary>Estimated memory charged against the budget.</summary>
        public static long EstimatedSizeBytes { get { lock (sync) return size; } }
        /// <summary>Removes retained evidence.</summary>
        public static void Clear() { lock (sync) { entries.Clear(); lru.Clear(); size = 0; } }

        internal static bool TryGetOcsp(X509Certificate2 cert, X509Certificate2 issuer, out OcspResponse response)
            => TryGet(OcspKey(cert, issuer), out response);
        internal static void PutOcsp(X509Certificate2 cert, X509Certificate2 issuer, OcspResponse response)
        {
            if (!Enabled) return;
            var parsed = response;
            var expires = parsed.Responses.Select(r => r.NextUpdate ?? parsed.ProducedAt + DefaultLifetime).Min();
            Put(OcspKey(cert, issuer), response, expires, response.EncodedLength * 4L + 512);
        }
        internal static bool TryGetCrl(X509Certificate2 cert, X509Certificate2 issuer, out CertificateRevocationList crl)
            => TryGet(CrlKey(cert, issuer), out crl);
        internal static void PutCrl(X509Certificate2 cert, X509Certificate2 issuer, CertificateRevocationList crl)
        {
            if (!Enabled) return;
            var parsed = crl;
            Put(CrlKey(cert, issuer), crl, parsed.NextUpdate ?? parsed.ThisUpdate + DefaultLifetime, crl.EstimatedSize);
        }
        private static string OcspKey(X509Certificate2 cert, X509Certificate2 issuer)
            => "ocsp|" + issuer.Thumbprint + "|" + cert.SerialNumber;
        private static string CrlKey(X509Certificate2 cert, X509Certificate2 issuer)
        {
            var points = cert.Extensions["2.5.29.31"];
            return "crl|" + issuer.Thumbprint + "|" + (points == null ? cert.Thumbprint : Convert.ToBase64String(points.RawData));
        }
        private static bool TryGet<T>(string key, out T value) where T : class
        {
            value = null;
            if (!Enabled) return false;
            lock (sync)
            {
                if (!entries.TryGetValue(key, out var node)) return false;
                if (node.Value.Expires <= DateTime.UtcNow) { Remove(node); return false; }
                lru.Remove(node); lru.AddLast(node);
                value = (T)node.Value.Value;
                return true;
            }
        }
        private static void Put(string key, object value, DateTime expires, long estimatedSize)
        {
            if (expires <= DateTime.UtcNow) return;
            lock (sync)
            {
                if (estimatedSize > sizeLimitBytes) return;
                if (entries.TryGetValue(key, out var previous)) Remove(previous);
                entries[key] = lru.AddLast(new Entry { Key = key, Value = value, Expires = expires, Size = estimatedSize });
                size += estimatedSize;
                Trim();
            }
        }
        private static void Trim() { while (entries.Count > entryLimit || size > sizeLimitBytes) Remove(lru.First); }
        private static void Remove(LinkedListNode<Entry> node) { entries.Remove(node.Value.Key); lru.Remove(node); size -= node.Value.Size; }
    }
}
