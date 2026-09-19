using System;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Helper
{
    internal static class TaskApm
    {
        internal static IAsyncResult Begin<T>(Task<T> task, AsyncCallback callback, object state)
        {
            var completion = new TaskCompletionSource<T>(state, TaskCreationOptions.RunContinuationsAsynchronously);
            _ = CompleteAsync(task, completion, callback);
            return completion.Task;
        }
        private static async Task CompleteAsync<T>(Task<T> task, TaskCompletionSource<T> completion, AsyncCallback callback)
        {
            try { completion.TrySetResult(await task.ConfigureAwait(false)); }
            catch (OperationCanceledException) { completion.TrySetCanceled(); }
            catch (Exception error) { completion.TrySetException(error); }
            callback?.Invoke(completion.Task);
        }
    }
}
