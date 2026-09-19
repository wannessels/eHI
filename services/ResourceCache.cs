using System;

namespace Egelke.EHealth.Client.Services
{
    // A client owns the current resource; outstanding operations keep retired resources alive.
    internal sealed class ResourceCache<TKey, TValue> : IDisposable where TValue : class
    {
        private readonly object sync = new object();
        private readonly Func<TKey, TKey, bool> matches;
        private Entry current;
        private bool disposed;

        private sealed class Entry
        {
            internal TKey Key;
            internal TValue Value;
            internal int Users;
            internal bool Retired;
        }

        internal ResourceCache(Func<TKey, TKey, bool> matches) { this.matches = matches; }

        internal Lease Acquire(TKey key, Func<TKey, TValue> create)
        {
            lock (sync)
            {
                if (disposed) throw new ObjectDisposedException(nameof(ResourceCache<TKey, TValue>));
                if (current == null || !matches(current.Key, key))
                {
                    // A failed replacement must not invalidate the existing resource.
                    var replacement = new Entry { Key = key, Value = create(key) };
                    Retire(current);
                    current = replacement;
                }
                var entry = current;
                entry.Users++;
                return new Lease(entry.Value, () => Release(entry));
            }
        }

        private void Release(Entry entry)
        {
            lock (sync)
            {
                if (--entry.Users == 0 && entry.Retired) (entry.Value as IDisposable)?.Dispose();
            }
        }

        private static void Retire(Entry entry)
        {
            if (entry == null) return;
            entry.Retired = true;
            if (entry.Users == 0) (entry.Value as IDisposable)?.Dispose();
        }

        public void Dispose()
        {
            lock (sync)
            {
                if (disposed) return;
                disposed = true;
                Retire(current);
                current = null;
            }
        }

        internal sealed class Lease : IDisposable
        {
            private Action release;
            internal TValue Value { get; }
            internal Lease(TValue value, Action release) { Value = value; this.release = release; }
            public void Dispose() { System.Threading.Interlocked.Exchange(ref release, null)?.Invoke(); }
        }
    }
}
