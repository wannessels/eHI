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
        internal sealed class Entry { internal X509Certificate2[] Path; internal DateTime Expires; }
        // Clear swaps the entire generation: a build already in progress can never
        // repopulate the cache used by subsequent operations.
        internal sealed class Generation
        {
            internal readonly ConcurrentDictionary<string, Entry> Entries = new();
            internal long Hits, Misses;
        }
        private static Generation current = new();
        private static long lifetimeTicks = TimeSpan.FromMinutes(10).Ticks;
        internal static Generation Capture() => Volatile.Read(ref current);
        /// <summary>How long a built path is reused, ten minutes by default; zero disables the cache.</summary>
        public static TimeSpan Lifetime
        {
            get => TimeSpan.FromTicks(Interlocked.Read(ref lifetimeTicks));
            set { Interlocked.Exchange(ref lifetimeTicks, value.Ticks); Clear(); }
        }
        /// <summary>Maximum number of retained paths.</summary>
        public static int EntryLimit { get; set; } = 1024;
        /// <summary>Number of retained paths.</summary>
        public static int Count => Capture().Entries.Count;
        /// <summary>Paths served from the cache since the last Clear.</summary>
        public static long Hits => Interlocked.Read(ref Capture().Hits);
        /// <summary>Lookups that required a platform chain build since the last Clear.</summary>
        public static long Misses => Interlocked.Read(ref Capture().Misses);
        /// <summary>Removes retained paths and resets the counters.</summary>
        public static void Clear() => Interlocked.Exchange(ref current, new Generation());

        internal static string Key(X509Certificate2 certificate, X509Certificate2Collection extraStore, X509Certificate2Collection trustStore, bool disableDownloads)
        {
            // System trust can change outside this library. Leave its trust decision
            // to the platform on every call rather than caching a successful status.
            if (trustStore == null) return null;
            var key = new StringBuilder(certificate.Thumbprint).Append('|').Append(disableDownloads);
            if (extraStore != null)
                foreach (string thumbprint in extraStore.Cast<X509Certificate2>().Select(c => c.Thumbprint).OrderBy(t => t, StringComparer.Ordinal)) key.Append('|').Append(thumbprint);
            key.Append("|trust");
            foreach (string thumbprint in trustStore.Cast<X509Certificate2>().Select(c => c.Thumbprint).OrderBy(t => t, StringComparer.Ordinal)) key.Append('|').Append(thumbprint);
            return key.ToString();
        }
        // Copies share the platform certificate handle, so a hit decodes nothing; callers dispose their copies.
        internal static Chain TryGet(Generation generation, string key, DateTime validationTime)
        {
            var chain = Lookup(generation, key, validationTime);
            Interlocked.Increment(ref chain == null ? ref generation.Misses : ref generation.Hits);
            return chain;
        }
        private static Chain Lookup(Generation generation, string key, DateTime validationTime)
        {
            if (key == null || Lifetime <= TimeSpan.Zero || !ReferenceEquals(generation, Capture())) return null;
            var entries = generation.Entries;
            if (!entries.TryGetValue(key, out var entry)) return null;
            if (entry.Expires <= DateTime.UtcNow) { entries.TryRemove(key, out _); return null; }
            if (entry.Path.Any(certificate => !CryptoEncoding.ValidAt(certificate, validationTime))) return null;
            var chain = new Chain();
            foreach (var certificate in entry.Path) chain.ChainElements.Add(new ChainElement { Certificate = new X509Certificate2(certificate) });
            return chain;
        }
        internal static void Put(Generation generation, string key, Chain chain)
        {
            if (key == null || Lifetime <= TimeSpan.Zero || !ReferenceEquals(generation, Capture()) || chain.ChainStatus.Count != 0 || chain.ChainElements.Any(element => element.ChainElementStatus.Count != 0)) return;
            var entries = generation.Entries;
            if (entries.Count >= EntryLimit)
            {
                foreach (var stale in entries.Where(pair => pair.Value.Expires <= DateTime.UtcNow).ToArray()) entries.TryRemove(stale.Key, out _);
                if (entries.Count >= EntryLimit) entries.Clear();
            }
            entries[key] = new Entry { Path = chain.ChainElements.Select(element => new X509Certificate2(element.Certificate)).ToArray(), Expires = DateTime.UtcNow + Lifetime };
        }
    }
}
