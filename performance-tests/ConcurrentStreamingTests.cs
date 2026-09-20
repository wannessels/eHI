using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

[Collection("Revocation")]
public class ConcurrentStreamingTests
{
    [Fact]
    public async Task SharedContextsHandleAsyncOnlyInputsAndIndependentCancellation()
    {
        using var key = RSA.Create(2048); var sender = new WebKey(key);
        var recipient = new SecretKey(new byte[] { 1 }, RandomNumberGenerator.GetBytes(16));
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, true).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, true).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection());
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        var bytes = Enumerable.Range(0, 8).Select(i => RandomNumberGenerator.GetBytes(2 * 1024 * 1024 + i)).ToArray();
        var inputs = bytes.Select(value => new AsyncOnlyInput(value, release.Task)).ToArray();
        try
        {
            var requests = inputs.Select((input, index) => sealer.SealAsync(input, recipient,
                index == 0 ? cancellation.Token : CancellationToken.None, Array.Empty<EncryptionToken>())).ToArray();
            Assert.All(requests, task => Assert.False(task.IsCompleted));
            cancellation.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => requests[0]);
            Assert.All(requests.Skip(1), task => Assert.False(task.IsCompleted));
            release.SetResult();
            await Task.WhenAll(requests.Skip(1).Select(async (request, index) =>
            {
                using var encrypted = await request;
                var result = await receiver.UnsealAsync(encrypted, sender, recipient);
                using (result.UnsealedData)
                {
                    Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
                    Assert.Equal(SHA256.HashData(bytes[index + 1]), await RuntimeCompat.HashStreamAsync(result.UnsealedData));
                }
            }));
            Assert.All(inputs, input => Assert.True(input.CanRead));
        }
        finally
        {
            release.TrySetResult(); foreach (var input in inputs) input.Dispose();
            (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose();
        }
    }

    [Fact]
    public async Task OuterSignatureRetryDoesNotReplaySinglePassInput()
    {
        using var key = new RetryRsa(); var sender = new WebKey(new byte[] { 4, 5, 6 }, key);
        var recipient = new SecretKey(new byte[] { 1 }, new byte[16]);
        var sealer = new DataSealerFactory(NullLoggerFactory.Instance, true).Create(Level.B_Level, sender);
        var receiver = new DataUnsealerFactory(NullLoggerFactory.Instance, true).Create(null, new X509Certificate2Collection(), new X509Certificate2Collection());
        int previous = Settings.Default.SignRetries; Settings.Default.SignRetries = 1;
        try
        {
            var bytes = RandomNumberGenerator.GetBytes(65537);
            using var input = new AsyncOnlyInput(bytes, Task.CompletedTask);
            using var encrypted = await sealer.SealAsync(input, recipient, Array.Empty<EncryptionToken>());
            Assert.Equal(3, key.SignCalls);
            Assert.Equal(bytes.Length, input.BytesRead);
            var result = await receiver.UnsealAsync(encrypted, sender, recipient);
            using (result.UnsealedData)
            {
                Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
                Assert.Equal(SHA256.HashData(bytes), RuntimeCompat.HashStream(result.UnsealedData));
            }
        }
        finally { Settings.Default.SignRetries = previous; (sealer as IDisposable)?.Dispose(); (receiver as IDisposable)?.Dispose(); }
    }

    private sealed class AsyncOnlyInput : Stream
    {
        private readonly byte[] content; private readonly Task ready; private bool disposed;
        internal int BytesRead { get; private set; }
        internal AsyncOnlyInput(byte[] content, Task ready) { this.content = content; this.ready = ready; }
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            RuntimeCompat.ThrowIfDisposed(disposed, this); await ready.WaitAsync(token);
            int count = Math.Min(buffer.Length, Math.Min(17011, content.Length - BytesRead));
            content.AsMemory(BytesRead, count).CopyTo(buffer); BytesRead += count; return count;
        }
        public override int Read(byte[] b, int o, int c) => throw new InvalidOperationException("Synchronous input reads are not allowed");
        public override bool CanRead => !disposed; public override bool CanSeek => false; public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { } public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
        public override void SetLength(long n) => throw new NotSupportedException(); public override void Write(byte[] b, int o, int c) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { disposed = true; base.Dispose(disposing); }
    }
    private sealed class RetryRsa : RSA
    {
        private readonly RSA inner = RSA.Create(2048);
        internal int SignCalls;
        public override byte[] SignHash(byte[] hash, HashAlgorithmName name, RSASignaturePadding padding)
        {
            if (++SignCalls == 2) throw new CryptographicException("Simulated transient signing-provider failure");
            return inner.SignHash(hash, name, padding);
        }
        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName name, RSASignaturePadding padding) => inner.VerifyHash(hash, signature, name, padding);
        public override RSAParameters ExportParameters(bool includePrivateParameters) => inner.ExportParameters(includePrivateParameters);
        public override void ImportParameters(RSAParameters parameters) => inner.ImportParameters(parameters);
        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding) => inner.Encrypt(data, padding);
        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding) => inner.Decrypt(data, padding);
        protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
    }
}
