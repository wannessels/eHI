using System;
using System.Diagnostics.Metrics;
using System.IO;
using System.Security.Cryptography;
using System.ServiceModel;
using System.Threading;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Sender;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

[Collection("Revocation")]
public class DefaultPolicyTests
{
    [Theory]
    [InlineData(8, false)] [InlineData(17, true)]
    public async Task DefaultThresholdKeepsSmallStreamsInMemoryAndSpillsLargerStreams(int mebibytes, bool spills)
    {
        Assert.Equal(16L * 1024 * 1024, Settings.Default.InMemorySize);
        long spillCount = 0;
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, subscriber) =>
        { if (instrument.Meter.Name == EHealthMetrics.MeterName && instrument.Name == "ehealth.spool.spills") subscriber.EnableMeasurementEvents(instrument); };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, state) => Interlocked.Add(ref spillCount, value));
        listener.Start();
        using var rsa = RSA.Create(2048);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, true).Create(Level.B_Level, new WebKey(rsa));
        try
        {
            using var input = new NonSeekableInput(new byte[mebibytes * 1024 * 1024]);
            using var output = await sealer.SealAsync(input, new SecretKey(new byte[] { 1 }, new byte[16]), Array.Empty<EncryptionToken>());
            Assert.Equal(spills, spillCount > 0);
        }
        finally { (sealer as IDisposable)?.Dispose(); }
    }
    private sealed class NonSeekableInput : MemoryStream
    {
        internal NonSeekableInput(byte[] data) : base(data, false) { }
        public override bool CanSeek => false;
    }

    [ServiceContract]
    public interface ITestPort
    {
        [OperationContract] void Unused();
    }
    private sealed class TestClient : ServiceClient<ITestPort>
    {
        internal TestClient() : base(new BasicHttpBinding(), new EndpointAddress("http://localhost/unused")) { }
        internal Task<int> RunAsync(Func<Task<int>> work) => RunOperationAsync(work, CancellationToken.None);
    }

    [Fact]
    public async Task DefaultFourSlotsAreSharedAcrossClientsAndStandaloneCrypto()
    {
        var firstClient = new TestClient(); var secondClient = new TestClient();
        using var rsa = RSA.Create(2048);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, true).Create(Level.B_Level, new WebKey(rsa));
        var release = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<int>[] active = new Task<int>[4]; Task<Stream> queued = null;
        using var input = new MemoryStream(new byte[32]);
        try
        {
            int entered = 0;
            for (int i = 0; i < active.Length; i++)
                active[i] = (i % 2 == 0 ? firstClient : secondClient).RunAsync(() => { entered++; return release.Task; });
            Assert.Equal(4, entered);
            queued = sealer.SealAsync(input, new SecretKey(new byte[] { 1 }, new byte[16]), Array.Empty<EncryptionToken>());
            Assert.False(queued.IsCompleted);
            Assert.Equal(0, input.Position);
            release.SetResult(1); await Task.WhenAll(active);
            using var output = await queued;
            Assert.True(output.Length > 0);
        }
        finally
        {
            release.TrySetResult(1);
            foreach (var task in active) if (task != null) await task;
            if (queued != null && queued.IsCompletedSuccessfully) queued.Result.Dispose();
            (sealer as IDisposable)?.Dispose(); firstClient.Abort(); secondClient.Abort();
        }
    }

    [Fact]
    public async Task ConfiguredDefaultReachesExistingClientsAndExplicitOverridesStayIndependent()
    {
        var previous = OperationPolicy.Default;
        var client = new TestClient(); var overridden = new TestClient();
        var release = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<int> active = null, queued = null;
        try
        {
            var custom = new OperationPolicy(2, TimeSpan.FromSeconds(30));
            overridden.OperationPolicy = custom;
            var configured = new OperationPolicy(1, TimeSpan.FromSeconds(10));
            OperationPolicy.Default = configured;
            Assert.Same(configured, client.OperationPolicy);
            Assert.Same(custom, overridden.OperationPolicy);
            Assert.Equal(1, client.OperationPolicy.MaximumConcurrency);
            Assert.Equal(TimeSpan.FromSeconds(10), client.OperationPolicy.Timeout);
            active = client.RunAsync(() => release.Task);
            queued = OperationPolicy.Default.RunAsync(_ => Task.FromResult(2));
            Assert.False(queued.IsCompleted);
            Assert.Equal(3, await overridden.RunAsync(() => Task.FromResult(3)));
            release.SetResult(1); await active; Assert.Equal(2, await queued);
            overridden.OperationPolicy = null;
            Assert.Same(configured, overridden.OperationPolicy);
            Assert.Throws<ArgumentNullException>(() => OperationPolicy.Default = null);
            Assert.Same(configured, OperationPolicy.Default);
        }
        finally
        {
            release.TrySetResult(1);
            if (active != null) await active;
            if (queued != null) await queued;
            OperationPolicy.Default = previous; client.Abort(); overridden.Abort();
        }
    }
}
