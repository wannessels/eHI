#if LEGACY_RUNTIME
using System;
using System.Security.Cryptography;

namespace Egelke.EHealth.Client.Pki.Compatibility
{
    public sealed class PortableIncrementalHash : IDisposable
    {
        private readonly HashAlgorithm hash;
        private PortableIncrementalHash(HashAlgorithmName name)
        {
            hash = name == HashAlgorithmName.SHA1 ? (HashAlgorithm)SHA1.Create() : name == HashAlgorithmName.SHA256 ? SHA256.Create() :
                name == HashAlgorithmName.SHA384 ? (HashAlgorithm)SHA384.Create() : name == HashAlgorithmName.SHA512 ? SHA512.Create() : throw new CryptographicException("Unsupported digest");
        }
        public static PortableIncrementalHash CreateHash(HashAlgorithmName name) => new PortableIncrementalHash(name);
        public void AppendData(byte[] data, int offset, int count) => hash.TransformBlock(data, offset, count, null, 0);
        public void AppendData(ReadOnlySpan<byte> data)
        {
            byte[] buffer = data.ToArray();
            try { AppendData(buffer, 0, buffer.Length); }
            finally { RuntimeCompat.ZeroMemory(buffer); }
        }
        public byte[] GetHashAndReset() { hash.TransformFinalBlock(Array.Empty<byte>(), 0, 0); byte[] result = hash.Hash; hash.Initialize(); return result; }
        public void Dispose() => hash.Dispose();
    }
}
#endif
