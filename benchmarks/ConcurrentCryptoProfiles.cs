using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging.Abstractions;

internal static class ConcurrentCryptoProfiles
{
    internal static async Task<object> RunAsync(int bytes, int concurrency, int requests, int thresholdMiB)
    {
        if (bytes < 1 || thresholdMiB < 0) throw new ArgumentOutOfRangeException();
        Settings.Default.InMemorySize = checked((long)thresholdMiB * 1024 * 1024);
        using var rsa = RSA.Create(2048); var sender = new WebKey(rsa);
        var recipient = new SecretKey(new byte[] { 1 }, RandomNumberGenerator.GetBytes(16));
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, true).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, true).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection());
        var payload = RandomNumberGenerator.GetBytes(bytes);
        var policy = new OperationPolicy(concurrency, TimeSpan.FromMinutes(2));
        async Task Request() => await policy.RunAsync(async _ =>
        {
            using var input = new MemoryStream(payload, false);
            using var sealedData = await sealer.SealAsync(input, recipient, Array.Empty<EncryptionToken>());
            var result = await receiver.UnsealAsync(sealedData, sender, recipient);
            using (result.UnsealedData)
            {
                if (result.SecurityInformation.ValidationStatus != ValidationStatus.Valid || result.UnsealedData.Length != bytes) throw new Exception("Round trip validation failed");
                result.UnsealedData.Position = bytes - 1;
                if (result.UnsealedData.ReadByte() != payload[bytes - 1]) throw new Exception("Content mismatch");
            }
            return 0;
        });
        try
        {
            var rounds = await ClosedLoop.RunAsync(concurrency, requests, Request);
            return new { Method = "Closed-loop workers; per-request latency includes dispatch, shared admission and seal+unseal. Immutable input is shared. Fresh process per scenario; no external services.", PayloadBytes = bytes, ThresholdMiB = thresholdMiB, Rounds = rounds };
        }
        finally { (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
    }
}
