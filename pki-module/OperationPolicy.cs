using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>One cooperative cancellation/deadline context for a complete crypto/service operation.</summary>
    public sealed class OperationScope : IDisposable
    {
        private static readonly AsyncLocal<OperationScope> current = new AsyncLocal<OperationScope>();
        private readonly OperationScope previous;
        private readonly CancellationTokenSource source;
        private readonly CancellationToken token;
        private readonly Stopwatch elapsed = Stopwatch.StartNew();
        private readonly TimeSpan timeout;
        /// <summary>The cancellation token flowing through the current operation.</summary>
        public static CancellationToken Cancellation => current.Value?.token ?? CancellationToken.None;
        internal static bool IsActive => current.Value != null;
        /// <summary>Starts a nested scope inheriting the caller's deadline.</summary>
        public OperationScope(CancellationToken cancellationToken, TimeSpan timeout) : this(cancellationToken, timeout, true) { }
        /// <summary>Starts a scope; shared operations can opt out of inheriting an individual waiter's deadline.</summary>
        public OperationScope(CancellationToken cancellationToken, TimeSpan timeout, bool inherit)
        {
            if (timeout <= TimeSpan.Zero || timeout.TotalMilliseconds > int.MaxValue) throw new ArgumentOutOfRangeException(nameof(timeout));
            previous = current.Value;
            this.timeout = inherit ? LimitTimeout(timeout) : timeout;
            source = inherit ? CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, Cancellation) : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            source.CancelAfter(this.timeout);
            token = source.Token;
            current.Value = this;
        }
        /// <summary>Caps a per-endpoint timeout to the remaining overall deadline.</summary>
        public static TimeSpan LimitTimeout(TimeSpan endpointTimeout)
        {
            Cancellation.ThrowIfCancellationRequested();
            var scope = current.Value;
            if (scope == null) return endpointTimeout;
            var remaining = scope.timeout - scope.elapsed.Elapsed;
            if (remaining <= TimeSpan.Zero) throw new OperationCanceledException(scope.token);
            return remaining < endpointTimeout ? remaining : endpointTimeout;
        }
        /// <summary>Copies with cancellation checks between chunks without owning either stream.</summary>
        public static void Copy(System.IO.Stream input, System.IO.Stream output)
        {
            var buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                int read;
                while (true)
                {
                    Cancellation.ThrowIfCancellationRequested();
                    read = input.Read(buffer, 0, buffer.Length);
                    if (read == 0) break;
                    output.Write(buffer, 0, read);
                }
            }
            finally { System.Buffers.ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
        }
        public void Dispose() { current.Value = previous; source.Dispose(); }
    }

    /// <summary>Bounds complete operations, including queueing, CPU work and external calls.</summary>
    public sealed class OperationPolicy
    {
        private readonly SemaphoreSlim admission;
        /// <summary>Shared process-wide policy. Configure a shared application policy for the measured task capacity.</summary>
        public static OperationPolicy Default { get; } = new OperationPolicy(16, TimeSpan.FromMinutes(1));
        /// <summary>Maximum duration, including time spent awaiting admission.</summary>
        public TimeSpan Timeout { get; }
        /// <summary>Creates a policy. Nested library calls retain the outer admission slot.</summary>
        public OperationPolicy(int maximumConcurrency, TimeSpan timeout)
        {
            if (maximumConcurrency < 1) throw new ArgumentOutOfRangeException(nameof(maximumConcurrency));
            if (timeout <= TimeSpan.Zero || timeout.TotalMilliseconds > int.MaxValue) throw new ArgumentOutOfRangeException(nameof(timeout));
            admission = new SemaphoreSlim(maximumConcurrency, maximumConcurrency); Timeout = timeout;
        }
        /// <summary>Runs a complete operation with cancellation and a deadline.</summary>
        public async Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken = default)
        {
            bool nested = OperationScope.IsActive;
            using (var scope = new OperationScope(cancellationToken, Timeout))
            {
                var token = OperationScope.Cancellation;
                if (!nested) await admission.WaitAsync(token).ConfigureAwait(false);
                try
                {
                    token.ThrowIfCancellationRequested();
                    T result = await operation(token).ConfigureAwait(false);
                    return result;
                }
                finally { if (!nested) admission.Release(); }
            }
        }
    }
}
