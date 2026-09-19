using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Xunit;

public class CancellationTests
{
    [Fact]
    public async Task AdmissionIsBoundedAndQueuedCancellationDoesNotRunWork()
    {
        var policy = new OperationPolicy(1, TimeSpan.FromSeconds(5));
        var release = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = policy.RunAsync(_ => release.Task);
        using (var cancellation = new CancellationTokenSource())
        {
            bool ran = false;
            var queued = policy.RunAsync(_ => { ran = true; return Task.FromResult(2); }, cancellation.Token);
            Assert.False(queued.IsCompleted);
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => queued);
            Assert.False(ran);
            release.SetResult(1);
            Assert.Equal(1, await first);
            Assert.Equal(3, await policy.RunAsync(_ => Task.FromResult(3)));
            Assert.False(OperationScope.Cancellation.CanBeCanceled);
        }
    }

    [Fact]
    public async Task DeadlineCancelsActiveWorkAndNestedCallsDoNotDeadlock()
    {
        var policy = new OperationPolicy(1, TimeSpan.FromMilliseconds(100));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => policy.RunAsync(async token =>
        {
            await policy.RunAsync(async inner => { await Task.Delay(10000, inner); return 0; });
            return 1;
        }));
    }

    [Fact]
    public async Task CancellingOneWaiterDoesNotCancelOtherWaiters()
    {
        var flights = new AsyncSingleFlight<string, int>();
        var completion = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken shared = default;
        using (var cancellation = new CancellationTokenSource())
        {
            var first = flights.RunAsync("key", token => { shared = token; return completion.Task; }, cancellation.Token);
            var second = flights.RunAsync("key", _ => throw new Exception("duplicate"), CancellationToken.None);
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
            Assert.False(shared.IsCancellationRequested);
            completion.SetResult(42);
            Assert.Equal(42, await second);
        }
    }

    [Fact]
    public async Task LastCancelledWaiterStopsWorkAndAllowsRetry()
    {
        var flights = new AsyncSingleFlight<string, int>();
        var stopped = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using (var cancellation = new CancellationTokenSource())
        {
            var task = flights.RunAsync("key", async token =>
            {
                try { await Task.Delay(10000, token); return 1; }
                finally { stopped.TrySetResult(true); }
            }, cancellation.Token);
            cancellation.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
            await stopped.Task.WaitAsync(TimeSpan.FromSeconds(2));
            Assert.Equal(2, await flights.RunAsync("key", () => Task.FromResult(2)));
        }
    }

    [Fact]
    public async Task Rfc3161HonorsCallerCancellationDuringHttp()
    {
        using (var server = new PkiFixture.FixtureServer())
        using (var cancellation = new CancellationTokenSource())
        {
            server.DelayMilliseconds = 1000;
            var provider = new Rfc3161TimestampProvider(new Uri(server.Url + "tsa"));
            var task = provider.GetTimestampFromDocumentHashAsync(new byte[32], "http://www.w3.org/2001/04/xmlenc#sha256", cancellation.Token);
            cancellation.CancelAfter(30);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        }
    }

    [Fact]
    public void CancellationStopsCryptoCopyWithoutClosingCallerStreams()
    {
        using (var cancellation = new CancellationTokenSource())
        using (var scope = new OperationScope(cancellation.Token, TimeSpan.FromSeconds(5)))
        using (var source = new CancellingStream(cancellation))
        using (var output = new MemoryStream())
        {
            Assert.ThrowsAny<OperationCanceledException>(() => OperationScope.Copy(source, output));
            Assert.True(source.CanRead);
            Assert.True(output.CanWrite);
            Assert.True(output.Length < source.Length);
        }
    }
    private sealed class CancellingStream : MemoryStream
    {
        private readonly CancellationTokenSource cancellation;
        internal CancellingStream(CancellationTokenSource cancellation) : base(new byte[1024 * 1024]) { this.cancellation = cancellation; }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int read = base.Read(buffer, offset, count); cancellation.Cancel(); return read;
        }
    }
}
