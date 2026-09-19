using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;

namespace Egelke.EHealth.Client.Helper
{
    internal sealed class RequestDeadline
    {
        private readonly Stopwatch elapsed = Stopwatch.StartNew();
        private readonly TimeSpan timeout;
        internal RequestDeadline(TimeSpan timeout)
        {
            if (timeout <= TimeSpan.Zero) throw new TimeoutException("The operation deadline has expired");
            this.timeout = timeout;
        }
        internal TimeSpan Remaining
        {
            get
            {
                var remaining = timeout - elapsed.Elapsed;
                if (remaining <= TimeSpan.Zero) throw new TimeoutException("The operation deadline has expired");
                return remaining;
            }
        }

        internal static async Task<T> WaitAsync<T>(Task<T> operation, TimeSpan timeout)
        {
            using (var timer = System.Threading.CancellationTokenSource.CreateLinkedTokenSource(OperationScope.Cancellation))
            {
                OperationScope.Cancellation.ThrowIfCancellationRequested();
                var expired = Task.Delay(timeout, timer.Token);
                if (await Task.WhenAny(operation, expired).ConfigureAwait(false) != operation)
                {
                    OperationScope.Cancellation.ThrowIfCancellationRequested();
                    throw new TimeoutException("The operation deadline has expired");
                }
                timer.Cancel();
                return await operation.ConfigureAwait(false);
            }
        }
    }
}
