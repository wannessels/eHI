using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>Shares in-flight operations, including failures, without retaining completed tasks.</summary>
    public sealed class AsyncSingleFlight<TKey, TValue>
    {
        private readonly ConcurrentDictionary<TKey, Lazy<Task<TValue>>> pending = new ConcurrentDictionary<TKey, Lazy<Task<TValue>>>();

        /// <summary>Runs one operation per key. A later call may retry after completion.</summary>
        public Task<TValue> RunAsync(TKey key, Func<Task<TValue>> operation)
        {
            return pending.GetOrAdd(key, k => new Lazy<Task<TValue>>(() => RunCoreAsync(k, operation))).Value;
        }

        private async Task<TValue> RunCoreAsync(TKey key, Func<Task<TValue>> operation)
        {
            try { return await operation().ConfigureAwait(false); }
            finally { pending.TryRemove(key, out _); }
        }
    }
}
