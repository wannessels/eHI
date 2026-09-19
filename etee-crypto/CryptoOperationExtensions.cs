using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Egelke.EHealth.Etee.Crypto.Store;

namespace Egelke.EHealth.Etee.Crypto
{
    /// <summary>Cancellation-aware operations. Existing interfaces and synchronous callers remain compatible.</summary>
    public static class CryptoOperationExtensions
    {
        public static Task<Stream> SealAsync(this IDataSealer sealer, Stream input, CancellationToken cancellationToken, params EncryptionToken[] recipients)
            => OperationPolicy.Default.RunAsync(_ => sealer.SealAsync(input, recipients), cancellationToken);
        public static Task<Stream> SealAsync(this IDataSealer sealer, Stream input, CancellationToken cancellationToken, params X509Certificate2[] recipients)
            => OperationPolicy.Default.RunAsync(_ => sealer.SealAsync(input, recipients), cancellationToken);
        public static Task<Stream> SealAsync(this IDataSealer sealer, Stream input, CancellationToken cancellationToken, params WebKey[] recipients)
            => OperationPolicy.Default.RunAsync(_ => sealer.SealAsync(input, recipients), cancellationToken);
        public static Task<Stream> SealAsync(this IDataSealer sealer, Stream input, SecretKey key, CancellationToken cancellationToken, params EncryptionToken[] recipients)
            => OperationPolicy.Default.RunAsync(_ => sealer.SealAsync(input, key, recipients), cancellationToken);
        public static Task<Stream> SealAsync(this IDataSealer sealer, Stream input, SecretKey key, EncryptionToken[] recipients, WebKey[] webKeys, CancellationToken cancellationToken)
            => OperationPolicy.Default.RunAsync(_ => sealer.SealAsync(input, key, recipients, webKeys), cancellationToken);
        public static Task<UnsealResult> UnsealAsync(this IDataUnsealer unsealer, Stream input, CancellationToken cancellationToken)
            => OperationPolicy.Default.RunAsync(_ => unsealer.UnsealAsync(input), cancellationToken);
        public static Task<UnsealResult> UnsealAsync(this IDataUnsealer unsealer, Stream input, WebKey sender, CancellationToken cancellationToken)
            => OperationPolicy.Default.RunAsync(_ => unsealer.UnsealAsync(input, sender), cancellationToken);
        public static Task<UnsealResult> UnsealAsync(this IDataUnsealer unsealer, Stream input, SecretKey key, CancellationToken cancellationToken)
            => OperationPolicy.Default.RunAsync(_ => unsealer.UnsealAsync(input, key), cancellationToken);
        public static Task<UnsealResult> UnsealAsync(this IDataUnsealer unsealer, Stream input, WebKey sender, SecretKey key, CancellationToken cancellationToken)
            => OperationPolicy.Default.RunAsync(_ => unsealer.UnsealAsync(input, sender, key), cancellationToken);
        public static Task<SignatureSecurityInformation> VerifyAsync(this IDataVerifier verifier, Stream input, CancellationToken cancellationToken, WebKey sender = null)
            => OperationPolicy.Default.RunAsync(_ => verifier.VerifyAsync(input, sender), cancellationToken);
        public static Task<TimemarkedResult<SignatureSecurityInformation>> VerifyAsync(this ITmaDataVerifier verifier, Stream input, System.DateTime date, CancellationToken cancellationToken)
            => OperationPolicy.Default.RunAsync(_ => verifier.VerifyAsync(input, date), cancellationToken);
        public static Task<Stream> CompleteAsync(this IDataCompleter completer, Stream input, CancellationToken cancellationToken)
            => OperationPolicy.Default.RunAsync(_ => completer.CompleteAsync(input), cancellationToken);
        public static Task<TimemarkedResult<Stream>> CompleteAsync(this ITmaDataCompleter completer, Stream input, CancellationToken cancellationToken)
            => OperationPolicy.Default.RunAsync(_ => completer.CompleteAsync(input), cancellationToken);
        public static Task<CertificateSecurityInformation> VerifyAsync(this EncryptionToken token, bool checkRevocation, CancellationToken cancellationToken)
            => OperationPolicy.Default.RunAsync(_ => token.VerifyAsync(checkRevocation), cancellationToken);
    }
}
