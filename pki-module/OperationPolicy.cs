using System;
using System.Diagnostics;
using System.IO;
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
        private bool admitted;
        /// <summary>The cancellation token flowing through the current operation.</summary>
        public static CancellationToken Cancellation => current.Value?.token ?? CancellationToken.None;
        internal static bool IsAdmitted => current.Value?.admitted == true;
        internal void MarkAdmitted() { admitted = true; }
        /// <summary>Starts a nested scope inheriting the caller's deadline.</summary>
        public OperationScope(CancellationToken cancellationToken, TimeSpan timeout) : this(cancellationToken, timeout, true) { }
        /// <summary>Starts a scope; shared operations can opt out of inheriting an individual waiter's deadline.</summary>
        public OperationScope(CancellationToken cancellationToken, TimeSpan timeout, bool inherit)
        {
            if (timeout <= TimeSpan.Zero || timeout.TotalMilliseconds > int.MaxValue) throw new ArgumentOutOfRangeException(nameof(timeout));
            previous = current.Value;
            admitted = inherit && (previous?.admitted ?? false);
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
        /// <summary>Copies asynchronously with the current deadline without owning either stream.</summary>
        public static async Task CopyAsync(System.IO.Stream input, System.IO.Stream output)
        {
            var buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(81920);
            var cancellation = Cancellation;
            try
            {
                while (true)
                {
                    cancellation.ThrowIfCancellationRequested();
                    int read = await input.ReadAsync(buffer.AsMemory(), cancellation).ConfigureAwait(false);
                    if (read == 0) break;
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellation).ConfigureAwait(false);
                }
            }
            finally { System.Buffers.ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
        }
        /// <summary>Restores the enclosing operation scope.</summary>
        public void Dispose() { current.Value = previous; source.Dispose(); }
    }

    /// <summary>Bounds complete operations, including queueing, CPU work and external calls.</summary>
    public sealed class OperationPolicy
    {
        private readonly SemaphoreSlim admission;
        private static OperationPolicy defaultPolicy = new OperationPolicy(4, TimeSpan.FromMinutes(1));
        /// <summary>Shared process-wide policy, initially four operations with a one-minute deadline.</summary>
        /// <remarks>
        /// Configure this at application startup. Clients without an explicit policy use the current default.
        /// Replacing it does not cancel or migrate operations already running or queued on the previous policy.
        /// </remarks>
        public static OperationPolicy Default
        {
            get => Volatile.Read(ref defaultPolicy);
            set
            {
                RuntimeCompat.ThrowIfNull(value, nameof(value));
                Volatile.Write(ref defaultPolicy, value);
            }
        }
        /// <summary>Maximum number of complete operations admitted concurrently by this policy.</summary>
        public int MaximumConcurrency { get; }
        /// <summary>Maximum duration, including time spent awaiting admission.</summary>
        public TimeSpan Timeout { get; }
        /// <summary>Creates a policy. Nested library calls retain the outer admission slot.</summary>
        public OperationPolicy(int maximumConcurrency, TimeSpan timeout)
        {
            if (maximumConcurrency < 1) throw new ArgumentOutOfRangeException(nameof(maximumConcurrency));
            if (timeout <= TimeSpan.Zero || timeout.TotalMilliseconds > int.MaxValue) throw new ArgumentOutOfRangeException(nameof(timeout));
            admission = new SemaphoreSlim(maximumConcurrency, maximumConcurrency);
            MaximumConcurrency = maximumConcurrency; Timeout = timeout;
        }
        /// <summary>Runs a complete operation with cancellation and a deadline.</summary>
        public Task<T> RunAsync<T>(Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken = default)
            => RunAsync("operation", operation, cancellationToken);
        /// <summary>Runs a named operation; top-level runs are reported through <see cref="EHealthMetrics"/>, nested runs belong to their enclosing operation.</summary>
        public async Task<T> RunAsync<T>(string name, Func<CancellationToken, Task<T>> operation, CancellationToken cancellationToken = default)
        {
            bool nested = OperationScope.IsAdmitted;
            long started = Stopwatch.GetTimestamp(); string outcome = "ok";
            using (var scope = new OperationScope(cancellationToken, Timeout))
            {
                var token = OperationScope.Cancellation;
                try
                {
                    if (!nested)
                    {
                        await admission.WaitAsync(token).ConfigureAwait(false);
                        EHealthMetrics.QueueDuration.Record(RuntimeCompat.GetElapsedTime(started).TotalMilliseconds, new TagList { { "operation", name } });
                        EHealthMetrics.ActiveOperations.Add(1, new TagList { { "operation", name } });
                    }
                    scope.MarkAdmitted();
                    try
                    {
                        token.ThrowIfCancellationRequested();
                        return await operation(token).ConfigureAwait(false);
                    }
                    finally
                    {
                        if (!nested) { admission.Release(); EHealthMetrics.ActiveOperations.Add(-1, new TagList { { "operation", name } }); }
                    }
                }
                catch (Exception error) { outcome = EHealthMetrics.Outcome(error); throw; }
                finally
                {
                    if (!nested) EHealthMetrics.Record(EHealthMetrics.Operations, EHealthMetrics.OperationDuration, started, new TagList { { "operation", name }, { "outcome", outcome } });
                }
            }
        }
    }
}
