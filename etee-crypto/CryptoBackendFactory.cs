using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Etee.Crypto
{
    internal static class CryptoBackendFactory
    {
        internal static TripleWrapper Wrapper(bool native, Level level, WebKey key, ITimestampProvider timestamps, ILoggerFactory logger)
            => native ? new TripleWrapper(level, key, timestamps, logger.CreateLogger<TripleWrapper>())
                : new BouncyCastleTripleWrapper(level, key, timestamps, logger.CreateLogger<TripleWrapper>());
        internal static TripleWrapper Wrapper(bool native, Level level, X509Certificate2 authentication, X509Certificate2 signature, ITimestampProvider timestamps, X509Certificate2Collection extra, ILoggerFactory logger)
            => native ? new TripleWrapper(level, authentication, signature, timestamps, extra, logger.CreateLogger<TripleWrapper>())
                : new BouncyCastleTripleWrapper(level, authentication, signature, timestamps, extra, logger.CreateLogger<TripleWrapper>());
        internal static TripleUnwrapper Unwrapper(bool native, Level? level, ITimemarkProvider timemark, X509Certificate2Collection encryption, X509Certificate2Collection authentication, WebKey[] keys, ILoggerFactory logger)
            => native ? new TripleUnwrapper(level, timemark, encryption, authentication, keys, logger.CreateLogger<TripleUnwrapper>())
                : new BouncyCastleTripleUnwrapper(level, timemark, encryption, authentication, keys, logger.CreateLogger<TripleUnwrapper>());
    }
}
