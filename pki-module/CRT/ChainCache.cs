using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>Bounded cache of successfully built certificate paths, reused while every certificate in the path is valid at the requested time.</summary>
    public static class ChainCache
    {
        private sealed class Entry { internal X509Certificate2[] Path; internal DateTime Expires; }
        private static readonly ConcurrentDictionary<string, Entry> entries = new ConcurrentDictionary<string, Entry>();
        private static long hits, misses;
        /// <summary>How long a built path is reused, ten minutes by default; zero disables the cache.</summary>
        public static TimeSpan Lifetime { get; set; } = TimeSpan.FromMinutes(10);
        /// <summary>Maximum number of retained paths.</summary>
        public static int EntryLimit { get; set; } = 1024;
        /// <summary>Number of retained paths.</summary>
        public static int Count => entries.Count;
        /// <summary>Paths served from the cache since the last Clear.</summary>
        public static long Hits => Interlocked.Read(ref hits);
        /// <summary>Lookups that required a platform chain build since the last Clear.</summary>
        public static long Misses => Interlocked.Read(ref misses);
        /// <summary>Removes retained paths and resets the counters.</summary>
        public static void Clear() { entries.Clear(); Interlocked.Exchange(ref hits, 0); Interlocked.Exchange(ref misses, 0); }

        internal static string Key(X509Certificate2 certificate, X509Certificate2Collection extraStore)
        {
            var key = new StringBuilder(certificate.Thumbprint);
            if (extraStore != null)
                foreach (string thumbprint in extraStore.Cast<X509Certificate2>().Select(c => c.Thumbprint).OrderBy(t => t, StringComparer.Ordinal)) key.Append('|').Append(thumbprint);
            return key.ToString();
        }
        // Copies share the platform certificate handle, so a hit decodes nothing; callers dispose their copies.
        internal static Chain TryGet(string key, DateTime validationTime)
        {
            var chain = Lookup(key, validationTime);
            Interlocked.Increment(ref chain == null ? ref misses : ref hits);
            return chain;
        }
        private static Chain Lookup(string key, DateTime validationTime)
        {
            if (!entries.TryGetValue(key, out var entry)) return null;
            if (entry.Expires <= DateTime.UtcNow) { entries.TryRemove(key, out _); return null; }
            if (entry.Path.Any(certificate => !CryptoEncoding.ValidAt(certificate, validationTime))) return null;
            var chain = new Chain();
            foreach (var certificate in entry.Path) chain.ChainElements.Add(new ChainElement { Certificate = new X509Certificate2(certificate) });
            return chain;
        }
        internal static void Put(string key, Chain chain)
        {
            if (Lifetime <= TimeSpan.Zero || chain.ChainStatus.Count != 0 || chain.ChainElements.Any(element => element.ChainElementStatus.Count != 0)) return;
            if (entries.Count >= EntryLimit)
            {
                foreach (var stale in entries.Where(pair => pair.Value.Expires <= DateTime.UtcNow).ToArray()) entries.TryRemove(stale.Key, out _);
                if (entries.Count >= EntryLimit) entries.Clear();
            }
            entries[key] = new Entry { Path = chain.ChainElements.Select(element => new X509Certificate2(element.Certificate)).ToArray(), Expires = DateTime.UtcNow + Lifetime };
        }
    }
}
