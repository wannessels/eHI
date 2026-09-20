global using RuntimeCompat = Egelke.EHealth.Client.Pki.RuntimeCompatibility;
#if LEGACY_RUNTIME
global using IncrementalHash = Egelke.EHealth.Client.Pki.Compatibility.PortableIncrementalHash;
global using CryptographicOperations = Egelke.EHealth.Client.Pki.RuntimeCompatibility;
global using SignedCms = Egelke.EHealth.Client.Pki.Compatibility.PortableSignedCms;
global using SignerInfo = Egelke.EHealth.Client.Pki.Compatibility.PortableSignerInfo;
global using Rfc3161TimestampToken = Egelke.EHealth.Client.Pki.Compatibility.PortableTimestampToken;
global using Rfc3161TimestampRequest = Egelke.EHealth.Client.Pki.Compatibility.PortableTimestampRequest;
#endif
