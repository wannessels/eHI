using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>Private-key handles for one signer, opened on demand up to a limit and leased per signature so concurrent callers sign in parallel.</summary>
    public sealed class SigningKeyPool : IDisposable
    {
        /// <summary>Handles opened per signer by default: the processor count. Set 1 for keys that cannot be used concurrently, such as smart cards.</summary>
        public static int DefaultLimit { get; set; } = Environment.ProcessorCount;

        private readonly Func<AsymmetricAlgorithm> open;
        private readonly bool owned;
        private readonly SemaphoreSlim slots;
        private readonly ConcurrentBag<AsymmetricAlgorithm> idle = new ConcurrentBag<AsymmetricAlgorithm>();
        private readonly List<AsymmetricAlgorithm> opened = new List<AsymmetricAlgorithm>();

        /// <summary>Creates a pool that opens handles with <paramref name="open"/>; owned handles are disposed with the pool.</summary>
        public SigningKeyPool(Func<AsymmetricAlgorithm> open, int limit, bool owned = true)
        {
            this.open = open; this.owned = owned;
            slots = new SemaphoreSlim(Math.Max(1, limit), Math.Max(1, limit));
        }
        /// <summary>A pool over a caller-provided key: platform keys are cloned per handle, other or non-exportable keys keep the single shared instance.</summary>
        public static SigningKeyPool ForWebKey(AsymmetricAlgorithm key, int limit)
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
        /// <summary>Leases a handle, waiting for one when all are in use.</summary>
        public async ValueTask<Lease> RentAsync(CancellationToken cancellation)
        {
            long started = Stopwatch.GetTimestamp();
            await slots.WaitAsync(cancellation).ConfigureAwait(false);
            return Acquire(started);
        }
        /// <summary>Leases a handle synchronously, waiting for one when all are in use.</summary>
        public Lease Rent(CancellationToken cancellation)
        {
            long started = Stopwatch.GetTimestamp();
            slots.Wait(cancellation);
            return Acquire(started);
        }
        private Lease Acquire(long started)
        {
            EHealthMetrics.SigningQueueDuration.Record(Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            if (idle.TryTake(out var key)) return new Lease(this, key);
            try { key = open(); }
            catch { slots.Release(); throw; }
            lock (opened) opened.Add(key);
            return new Lease(this, key);
        }
        private void Return(AsymmetricAlgorithm key) { idle.Add(key); slots.Release(); }
        /// <summary>Disposes owned handles.</summary>
        public void Dispose()
        {
            if (owned) lock (opened) foreach (var key in opened) key.Dispose();
            slots.Dispose();
        }
        /// <summary>A leased handle; disposing returns it to the pool.</summary>
        public readonly struct Lease : IDisposable
        {
            private readonly SigningKeyPool pool;
            /// <summary>The leased key.</summary>
            public AsymmetricAlgorithm Key { get; }
            internal Lease(SigningKeyPool pool, AsymmetricAlgorithm key) { this.pool = pool; Key = key; }
            /// <summary>Returns the key to the pool.</summary>
            public void Dispose() => pool.Return(Key);
        }
    }
}
