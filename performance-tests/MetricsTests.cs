using System;
using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

public class MetricsTests
{
    [Fact]
    public async Task TopLevelOperationsAndCachesAreReported()
    {
        var counts = new ConcurrentDictionary<string, long>(); var gauges = new ConcurrentDictionary<string, long>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, subscriber) => { if (instrument.Meter.Name == EHealthMetrics.MeterName) subscriber.EnableMeasurementEvents(instrument); };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            string key = instrument.Name; foreach (var tag in tags) key += ":" + tag.Value;
            if (instrument.IsObservable) gauges[instrument.Name] = value; else counts.AddOrUpdate(key, value, (_, total) => total + value);
        });
        listener.Start();
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa); var recipient = new SecretKey(new byte[] { 9 }, RandomNumberGenerator.GetBytes(16));
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, true).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, true).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection());
        try
        {
            using var input = new MemoryStream(new byte[] { 1, 2, 3 });
            using var sealedData = await sealer.SealAsync(input, recipient, Array.Empty<EncryptionToken>());
            var result = await receiver.UnsealAsync(sealedData, sender, recipient); result.UnsealedData.Dispose();
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
        listener.RecordObservableInstruments();
        Assert.True(counts.TryGetValue("ehealth.operations:seal:ok", out long seals) && seals >= 1);
        Assert.True(counts.TryGetValue("ehealth.operations:unseal:ok", out long unseals) && unseals >= 1);
        Assert.True(counts.ContainsKey("ehealth.operations.active:seal"));
        Assert.True(gauges.ContainsKey("ehealth.chain.cache.entries") && gauges.ContainsKey("ehealth.revocation.cache.entries"));
    }
}
