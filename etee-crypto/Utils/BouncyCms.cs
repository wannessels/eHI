using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto.Configuration;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Egelke.EHealth.Etee.Crypto.Utils
{
    // BouncyCastle handles payload cryptography and streaming. Detached metadata goes
    // through the same certificate, timestamp and revocation policy as native CMS.
    internal static class BouncyCms
    {
        internal const int BufferSize = 64 * 1024;

        internal static ITempStreamFactory Streams(Stream input) => input.Length - input.Position > Settings.Default.InMemorySize
            ? new TempFileStreamFactory() : new MemoryStreamFactory(input.Length - input.Position);

        internal sealed class Input : IDisposable
        {
            internal Stream Stream { get; }
            private readonly bool owned;
            internal Input(Stream input)
            {
                OperationScope.Cancellation.ThrowIfCancellationRequested();
                if (input.CanSeek) { Stream = input; return; }
                Stream = new CryptoSpool(); owned = true;
                try { OperationScope.Copy(input, Stream); Stream.Position = 0; }
                catch { Stream.Dispose(); throw; }
            }
            public void Dispose() { if (owned) Stream.Dispose(); }
        }

        internal static AsymmetricKeyParameter PublicKey(WebKey key) => PublicKeyFactory.CreateKey(key.NativeKey.ExportSubjectPublicKeyInfo());
        internal static AsymmetricKeyParameter PrivateKey(AsymmetricAlgorithm key)
        {
            byte[] encoded = key.ExportPkcs8PrivateKey();
            try { return PrivateKeyFactory.CreateKey(encoded); }
            finally { CryptographicOperations.ZeroMemory(encoded); }
        }

        internal sealed class Keys
        {
            private readonly ConcurrentDictionary<X509Certificate2, Lazy<AsymmetricKeyParameter>> certificates = new();
            private readonly ConcurrentDictionary<WebKey, Lazy<AsymmetricKeyParameter>> webKeys = new();
            internal AsymmetricKeyParameter Get(WebKey key) => webKeys.GetOrAdd(key, value => new(() => PrivateKey(value.NativeKey))).Value;
            internal AsymmetricKeyParameter Get(X509Certificate2 certificate) => certificates.GetOrAdd(certificate, value => new(() =>
            {
                using var key = (AsymmetricAlgorithm)value.GetRSAPrivateKey() ?? value.GetECDsaPrivateKey()
                    ?? throw new CryptographicException("An RSA or ECDSA private key is required");
                return PrivateKey(key);
            })).Value;
            internal void Clear() { certificates.Clear(); webKeys.Clear(); }
        }

        internal sealed class Processable : CmsProcessable
        {
            private readonly Stream input;
            internal Processable(Stream input) { this.input = input; }
            public void Write(Stream output) => OperationScope.Copy(input, output);
            public object GetContent() => input;
        }

        internal static CmsSignedData Metadata(CmsSignedDataParser parser)
        {
            var generator = new CmsSignedDataGenerator();
            generator.AddCertificates(parser.GetCertificates());
            generator.AddSigners(parser.GetSignerInfos());
            return generator.Generate(new CmsProcessableByteArray(Array.Empty<byte>()), false);
        }

        internal static void Embed(Stream output, Stream content, CmsSignedData metadata)
        {
            var generator = new CmsSignedDataStreamGenerator();
            generator.SetBufferSize(BufferSize);
            generator.AddCertificates(metadata.GetCertificates());
            generator.AddSigners(metadata.GetSignerInfos());
            using var signed = generator.Open(output, true);
            OperationScope.Copy(content, signed);
        }

        // Check the outer BER frame without materializing the payload. Definite-length
        // values are skipped; indefinite-length containers are walked with bounded depth.
        internal static void ValidateFrame(Stream input)
        {
            long start = input.Position;
            try
            {
                if (input.ReadByte() != 0x30) throw new InvalidMessageException("Expected a CMS sequence");
                SkipValue(input, true, 0);
                if (input.Position != input.Length) throw new InvalidMessageException("Trailing CMS data");
            }
            finally { input.Position = start; }
        }

        private static void SkipValue(Stream input, bool constructed, int depth)
        {
            OperationScope.Cancellation.ThrowIfCancellationRequested();
            int first = input.ReadByte();
            if (first < 0 || depth > 64) throw new InvalidMessageException("Invalid CMS frame");
            if (first == 0x80)
            {
                if (!constructed) throw new InvalidMessageException("Invalid indefinite CMS value");
                while (true)
                {
                    int tag = input.ReadByte();
                    if (tag < 0) throw new InvalidMessageException("Truncated CMS frame");
                    if (tag == 0)
                    {
                        if (input.ReadByte() != 0) throw new InvalidMessageException("Invalid CMS end marker");
                        break;
                    }
                    if ((tag & 31) == 31)
                    {
                        int part, count = 0;
                        do { part = input.ReadByte(); if (part < 0 || ++count > 6) throw new InvalidMessageException("Invalid CMS tag"); } while ((part & 128) != 0);
                    }
                    SkipValue(input, (tag & 32) != 0, depth + 1);
                }
                return;
            }
            long length = first;
            if (first > 0x80)
            {
                int count = first & 127;
                if (count > 8) throw new InvalidMessageException("Invalid CMS length");
                length = 0;
                for (int i = 0; i < count; i++)
                {
                    int part = input.ReadByte();
                    if (part < 0 || length > (long.MaxValue - part) / 256) throw new InvalidMessageException("Invalid CMS length");
                    length = length * 256 + part;
                }
            }
            if (length > input.Length - input.Position) throw new InvalidMessageException("Truncated CMS frame");
            input.Position += length;
        }
    }
}
