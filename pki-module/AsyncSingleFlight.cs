using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>Shares in-flight operations; the last cancelled waiter cancels the underlying work.</summary>
    public sealed class AsyncSingleFlight<TKey, TValue>
    {
        private sealed class Flight
        {
            internal readonly CancellationTokenSource Cancellation = new CancellationTokenSource();
            internal readonly TaskCompletionSource<TValue> Completion = new TaskCompletionSource<TValue>(TaskCreationOptions.RunContinuationsAsynchronously);
            internal int Waiters;
            internal bool Completed;
        }
        private readonly object sync = new object();
        private readonly Dictionary<TKey, Flight> pending = new Dictionary<TKey, Flight>();

        /// <summary>Runs one operation per key, allowing retries after completion.</summary>
        public Task<TValue> RunAsync(TKey key, Func<Task<TValue>> operation)
            => RunAsync(key, _ => operation(), CancellationToken.None);

        /// <summary>Cancels only this waiter unless all waiters have left.</summary>
        public Task<TValue> RunAsync(TKey key, Func<CancellationToken, Task<TValue>> operation, CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested) return Task.FromCanceled<TValue>(cancellationToken);
            Flight flight;
            bool start = false;
            lock (sync)
            {
                if (!pending.TryGetValue(key, out flight)) { flight = new Flight(); pending.Add(key, flight); start = true; }
                flight.Waiters++;
            }
            if (start) _ = ExecuteAsync(key, flight, operation);
            return WaitAsync(key, flight, cancellationToken);
        }
        private async Task ExecuteAsync(TKey key, Flight flight, Func<CancellationToken, Task<TValue>> operation)
        {
            try { flight.Completion.TrySetResult(await operation(flight.Cancellation.Token).ConfigureAwait(false)); }
            catch (OperationCanceledException) { flight.Completion.TrySetCanceled(); }
            catch (Exception error) { flight.Completion.TrySetException(error); _ = flight.Completion.Task.Exception; }
            finally
            {
                lock (sync)
                {
                    flight.Completed = true;
                    Remove(key, flight);
                    if (flight.Waiters == 0) flight.Cancellation.Dispose();
                }
            }
        }
        private async Task<TValue> WaitAsync(TKey key, Flight flight, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken.CanBeCanceled)
                {
                    var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    using (cancellationToken.Register(() => cancelled.TrySetResult(true)))
                    {
                        await Task.WhenAny(flight.Completion.Task, cancelled.Task).ConfigureAwait(false);
                        cancellationToken.ThrowIfCancellationRequested();
                    }
                }
                return await flight.Completion.Task.ConfigureAwait(false);
            }
            finally
            {
                bool cancel = false;
                lock (sync)
                {
                    if (--flight.Waiters == 0)
                    {
                        if (flight.Completed) flight.Cancellation.Dispose();
                        else { Remove(key, flight); cancel = true; }
                    }
                }
                if (cancel)
                {
                    try { flight.Cancellation.Cancel(); } catch (ObjectDisposedException) { }
                }
            }
        }
        private void Remove(TKey key, Flight flight)
        {
            if (pending.TryGetValue(key, out var current) && ReferenceEquals(current, flight)) pending.Remove(key);
        }
    }
}
