using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    // Private-key handles opened on demand, at most Settings.SigningKeyHandles per signer, so concurrent seals sign in parallel.
    internal sealed class SigningKeyPool : IDisposable
    {
        private readonly Func<AsymmetricAlgorithm> open;
        private readonly bool owned;
        private readonly SemaphoreSlim slots;
        private readonly ConcurrentBag<AsymmetricAlgorithm> idle = new ConcurrentBag<AsymmetricAlgorithm>();
        private readonly List<AsymmetricAlgorithm> opened = new List<AsymmetricAlgorithm>();

        internal SigningKeyPool(Func<AsymmetricAlgorithm> open, int limit, bool owned = true)
        {
            this.open = open; this.owned = owned;
            slots = new SemaphoreSlim(Math.Max(1, limit), Math.Max(1, limit));
        }
        // Only platform keys are cloned; a caller-implemented or non-exportable key keeps its single shared handle, serialized as before.
        internal static SigningKeyPool ForWebKey(AsymmetricAlgorithm key, int limit)
        {
            if (key.GetType().Assembly != typeof(RSA).Assembly) return new SigningKeyPool(() => key, 1, owned: false);
            try { Clone(key).Dispose(); return new SigningKeyPool(() => Clone(key), limit); }
            catch (CryptographicException) { return new SigningKeyPool(() => key, 1, owned: false); }
        }
        private static AsymmetricAlgorithm Clone(AsymmetricAlgorithm key)
        {
            switch (key)
            {
                case RSA rsa: { var copy = RSA.Create(); try { copy.ImportParameters(rsa.ExportParameters(true)); return copy; } catch { copy.Dispose(); throw; } }
                case ECDsa ec: { var copy = ECDsa.Create(); try { copy.ImportParameters(ec.ExportParameters(true)); return copy; } catch { copy.Dispose(); throw; } }
                default: throw new CryptographicException("RSA or ECDSA signing keys are required");
            }
        }
        internal async ValueTask<Lease> RentAsync(CancellationToken cancellation)
        {
            long started = Stopwatch.GetTimestamp();
            await slots.WaitAsync(cancellation).ConfigureAwait(false);
            EHealthMetrics.SigningQueueDuration.Record(Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            if (idle.TryTake(out var key)) return new Lease(this, key);
            try { key = open(); }
            catch { slots.Release(); throw; }
            lock (opened) opened.Add(key);
            return new Lease(this, key);
        }
        private void Return(AsymmetricAlgorithm key) { idle.Add(key); slots.Release(); }
        public void Dispose()
        {
            if (owned) lock (opened) foreach (var key in opened) key.Dispose();
            slots.Dispose();
        }
        internal readonly struct Lease : IDisposable
        {
            private readonly SigningKeyPool pool;
            internal AsymmetricAlgorithm Key { get; }
            internal Lease(SigningKeyPool pool, AsymmetricAlgorithm key) { this.pool = pool; Key = key; }
            public void Dispose() => pool.Return(Key);
        }
    }
}
