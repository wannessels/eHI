using System;
using System.Diagnostics;
using System.Formats.Asn1;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>Runtime-independent helpers shared by the supported library targets.</summary>
    public static class RuntimeCompatibility
    {
        public static TimeSpan GetElapsedTime(long start) => TimeSpan.FromSeconds((Stopwatch.GetTimestamp() - start) / (double)Stopwatch.Frequency);
        public static void ThrowIfNull(object value, string name) { if (value == null) throw new ArgumentNullException(name); }
        public static void ThrowIfDisposed(bool disposed, object instance) { if (disposed) throw new ObjectDisposedException(instance.GetType().FullName); }
        public static string ToHexString(ReadOnlySpan<byte> bytes)
        {
#if NET6_0_OR_GREATER
            return Convert.ToHexString(bytes);
#else
            const string digits = "0123456789ABCDEF";
            var chars = new char[bytes.Length * 2];
            for (int i = 0; i < bytes.Length; i++) { chars[2 * i] = digits[bytes[i] >> 4]; chars[2 * i + 1] = digits[bytes[i] & 15]; }
            return new string(chars);
#endif
        }
        public static byte[] FromHexString(string value)
        {
#if NET6_0_OR_GREATER
            return Convert.FromHexString(value);
#else
            if (value == null) throw new ArgumentNullException(nameof(value));
            if ((value.Length & 1) != 0) throw new FormatException("Odd hexadecimal length");
            var bytes = new byte[value.Length / 2];
            static int Digit(char c) => c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : throw new FormatException("Invalid hexadecimal digit");
            for (int i = 0; i < bytes.Length; i++) bytes[i] = (byte)((Digit(value[i * 2]) << 4) | Digit(value[i * 2 + 1]));
            return bytes;
#endif
        }
        public static byte[] RandomBytes(int count) { var bytes = new byte[count]; using (var random = RandomNumberGenerator.Create()) random.GetBytes(bytes); return bytes; }
        public static RSA CreateRsa(int bits)
        {
#if NETFRAMEWORK
            return new RSACng(bits);
#elif NETSTANDARD2_0
            if (System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows)) return new RSACng(bits);
            var rsa = RSA.Create(); rsa.KeySize = bits; return rsa;
#else
            return RSA.Create(bits);
#endif
        }
        public static DSA GetDsaPublicKey(X509Certificate2 certificate)
        {
#if NETSTANDARD2_0
            if (certificate.PublicKey.Oid.Value != "1.2.840.10040.4.1") return null;
            var parameters = CryptoEncoding.Sequence(certificate.PublicKey.EncodedParameters.RawData);
            static byte[] Integer(AsnReader reader)
            {
                var bytes = reader.ReadIntegerBytes().Span;
                if ((bytes[0] & 128) != 0) throw new CryptographicException("Negative DSA parameter");
                return (bytes.Length > 1 && bytes[0] == 0 ? bytes.Slice(1) : bytes).ToArray();
            }
            var value = new DSAParameters { P = Integer(parameters), Q = Integer(parameters), G = Integer(parameters) };
            parameters.ThrowIfNotEmpty();
            var keyReader = new AsnReader(certificate.PublicKey.EncodedKeyValue.RawData, AsnEncodingRules.DER); value.Y = Integer(keyReader); keyReader.ThrowIfNotEmpty();
            var key = DSA.Create(); try { key.ImportParameters(value); return key; } catch { key.Dispose(); throw; }
#else
            return certificate.GetDSAPublicKey();
#endif
        }
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining | System.Runtime.CompilerServices.MethodImplOptions.NoOptimization)]
        public static void ZeroMemory(Span<byte> bytes)
        {
#if NET6_0_OR_GREATER
            CryptographicOperations.ZeroMemory(bytes);
#else
            bytes.Clear();
#endif
        }
#if LEGACY_RUNTIME
        [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining | System.Runtime.CompilerServices.MethodImplOptions.NoOptimization)]
#endif
        public static bool FixedTimeEquals(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
        {
#if NET6_0_OR_GREATER
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(first, second);
#else
            if (first.Length != second.Length) return false;
            int difference = 0;
            for (int i = 0; i < first.Length; i++) difference |= first[i] ^ second[i];
            return difference == 0;
#endif
        }
        public static byte[] HashStream(Stream stream)
        { using (var hash = SHA256.Create()) return hash.ComputeHash(stream); }
        public static async Task<byte[]> HashStreamAsync(Stream stream, CancellationToken cancellation = default)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(81920);
            try
            {
                int read;
                while ((read = await stream.ReadAsync(buffer, 0, buffer.Length, cancellation).ConfigureAwait(false)) != 0) hash.AppendData(buffer, 0, read);
                return hash.GetHashAndReset();
            }
            finally { System.Buffers.ArrayPool<byte>.Shared.Return(buffer, true); }
        }
        public static byte[] SignEcHash(ECDsa key, byte[] hash)
        {
#if LEGACY_RUNTIME
            byte[] signature = key.SignHash(hash);
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence()) { writer.WriteIntegerUnsigned(signature.AsSpan(0, signature.Length / 2)); writer.WriteIntegerUnsigned(signature.AsSpan(signature.Length / 2)); }
            return writer.Encode();
#else
            return key.SignHash(hash, DSASignatureFormat.Rfc3279DerSequence);
#endif
        }
        public static bool VerifyEcHash(ECDsa key, byte[] hash, byte[] signature)
        {
#if LEGACY_RUNTIME
            return key.VerifyHash(hash, ToP1363(signature, (key.KeySize + 7) / 8));
#else
            return key.VerifyHash(hash, signature, DSASignatureFormat.Rfc3279DerSequence);
#endif
        }
        public static bool VerifyDsaHash(DSA key, byte[] hash, byte[] signature)
        {
            return key.VerifySignature(hash, ToP1363(signature, key.ExportParameters(false).Q.Length));
        }
        private static byte[] ToP1363(byte[] signature, int width)
        {
            var reader = new AsnReader(signature, AsnEncodingRules.DER); var sequence = reader.ReadSequence(); reader.ThrowIfNotEmpty();
            byte[] result = new byte[2 * width];
            for (int part = 0; part < 2; part++)
            {
                var value = sequence.ReadIntegerBytes().Span;
                if ((value[0] & 128) != 0) throw new CryptographicException("Negative signature integer");
                if (value.Length > 1 && value[0] == 0) value = value.Slice(1);
                if (value.Length > width) throw new CryptographicException("Oversized signature integer");
                value.CopyTo(result.AsSpan((part + 1) * width - value.Length));
            }
            sequence.ThrowIfNotEmpty(); return result;
        }
        public static byte[] ExportPublicKey(AsymmetricAlgorithm key)
        {
#if LEGACY_RUNTIME
            var method = key.GetType().GetMethod("ExportSubjectPublicKeyInfo", Type.EmptyTypes);
            if (method != null) return InvokeExport(key, method);
            if (key is RSA rsa) return Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(Org.BouncyCastle.Security.DotNetUtilities.GetRsaPublicKey(rsa)).GetEncoded();
            if (key is DSA dsa) return Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(Org.BouncyCastle.Security.DotNetUtilities.GetDsaPublicKey(dsa)).GetEncoded();
            if (key is ECDsaCng ec)
            {
                byte[] blob = ec.Key.Export(CngKeyBlobFormat.EccPublicBlob);
                int width = BitConverter.ToInt32(blob, 4);
                if (blob.Length != 8 + width * 2) throw new CryptographicException("Invalid EC public key blob");
                string curve = width == 32 ? "1.2.840.10045.3.1.7" : width == 48 ? "1.3.132.0.34" : width == 66 ? "1.3.132.0.35" : throw new CryptographicException("Unsupported EC curve");
                byte[] point = new byte[1 + width * 2]; point[0] = 4; Array.Copy(blob, 8, point, 1, width * 2);
                var writer = new AsnWriter(AsnEncodingRules.DER);
                using (writer.PushSequence())
                {
                    using (writer.PushSequence()) { writer.WriteObjectIdentifier("1.2.840.10045.2.1"); writer.WriteObjectIdentifier(curve); }
                    writer.WriteBitString(point);
                }
                return writer.Encode();
            }
            throw new NotSupportedException("The provider does not expose public-key encoding on this runtime");
#else
            return key.ExportSubjectPublicKeyInfo();
#endif
        }
        public static byte[] ExportPrivateKey(AsymmetricAlgorithm key)
        {
#if LEGACY_RUNTIME
            var method = key.GetType().GetMethod("ExportPkcs8PrivateKey", Type.EmptyTypes);
            if (method != null) return InvokeExport(key, method);
            if (key is ECDsaCng ec) return ec.Key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
            return Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(Org.BouncyCastle.Security.DotNetUtilities.GetKeyPair(key).Private).GetEncoded();
#else
            return key.ExportPkcs8PrivateKey();
#endif
        }
#if LEGACY_RUNTIME
        private static byte[] InvokeExport(AsymmetricAlgorithm key, System.Reflection.MethodInfo method)
        {
            try { return (byte[])method.Invoke(key, null); }
            catch (System.Reflection.TargetInvocationException error) when (error.InnerException != null)
            { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(error.InnerException).Throw(); throw; }
        }
#endif
        public static CryptoStream CreateCryptoStream(Stream stream, ICryptoTransform transform, CryptoStreamMode mode)
        {
#if LEGACY_RUNTIME
            return new CryptoStream(new Compatibility.LeaveOpenStream(stream), transform, mode);
#else
            return new CryptoStream(stream, transform, mode, true);
#endif
        }
        public static Task FlushFinalBlockAsync(CryptoStream stream, CancellationToken cancellation)
        {
#if LEGACY_RUNTIME
            cancellation.ThrowIfCancellationRequested(); stream.FlushFinalBlock(); return Task.CompletedTask;
#else
            return stream.FlushFinalBlockAsync(cancellation).AsTask();
#endif
        }
    }
}
