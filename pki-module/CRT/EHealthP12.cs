/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014 Egelke BVBA
 *
 *  eH-I is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  eH-I is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with eH-I.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Security.Cryptography.Pkcs;
using System.Formats.Asn1;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Collections;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;

namespace Egelke.EHealth.Client.Pki
{
    /// <summary>
    /// To read P12 files produced by eHealth. 
    /// </summary>
    public class EHealthP12 : IDictionary<String, X509Certificate2>, IDisposable
    {
        //        private const String SnRegExPattern = @"SERIALNUMBER=(?<sn>\d+)";
        private const String SnRegExPattern = @"SSIN=(?<sn>\d+)";


        /// <summary>
        /// Find the last version of the eHealth p12 file based on the inss of the provided eid cert.
        /// </summary>
        /// <remarks>Looks for the file in the default location (%USER_PROFILE%/ehealth/keystore)</remarks>
        /// <param name="eidCert">The eid cert of a person</param>
        /// <returns>The path of the p12 for that person</returns>
        public static string FindCorresponding(X509Certificate2 eidCert)
        {
            if (eidCert == null) throw new ArgumentNullException("eidCert");

            Regex snRegex = new Regex(SnRegExPattern);
            Match snMatch = snRegex.Match(eidCert.Subject);
            if (!snMatch.Success || !snMatch.Groups["sn"].Success) throw new ArgumentException("The inserted eID has an invalid subject: " + eidCert.Subject, "eidCert");
            string sn = snMatch.Groups["sn"].Value;


            string[] files = Directory.GetFiles(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "ehealth", "keystore"), "SSIN=" + sn + "*p12");
            Array.Sort(files);

            return files[files.Length - 1];
        }

        private readonly string password;
        private readonly Dictionary<string, X509Certificate2> store = new Dictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, Lazy<X509Certificate2>> certs = new ConcurrentDictionary<string, Lazy<X509Certificate2>>();
        private List<string> aliases;

        /// <summary>
        /// Create instance from file.
        /// </summary>
        /// <param name="file">Path to p12 store</param>
        /// <param name="pwd">The store password</param>
        public EHealthP12(String file, String pwd) : this(File.ReadAllBytes(file), pwd) { }

        /// <summary>
        /// Create instance from memory
        /// </summary>
        /// <param name="data">p12 store in memory</param>
        /// <param name="pwd">The store password</param>
        public EHealthP12(byte[] data, String pwd)
        {
            password = pwd;
#if LEGACY_RUNTIME
            // The bounded platform loader validates MAC/password/import limits first.
            // Older targets lack Pkcs12Info, so BC supplies aliases after that check.
            var framing = new AsnReader(data, AsnEncodingRules.BER);
            framing.ReadEncodedValue(); framing.ThrowIfNotEmpty();
            var imported = X509CertificateLoader.LoadPkcs12Collection(data, pwd, X509KeyStorageFlags.Exportable);
            try
            {
                var legacy = new Org.BouncyCastle.Pkcs.Pkcs12StoreBuilder().Build();
                using (var stream = new MemoryStream(data, false)) legacy.Load(stream, pwd?.ToCharArray());
                foreach (string alias in legacy.Aliases)
                {
                    byte[] encoded = legacy.GetCertificate(alias).Certificate.GetEncoded();
                    bool privateKey = legacy.IsKeyEntry(alias);
                    if (!privateKey) { SetCertificate(alias, new X509Certificate2(encoded)); continue; }
                    var matches = imported.Cast<X509Certificate2>().Where(c => c.HasPrivateKey == privateKey && c.RawData.SequenceEqual(encoded)).ToArray();
                    if (matches.Length == 0) throw new CryptographicException("Missing PKCS#12 certificate/key association");
                    SetCertificate(alias, new X509Certificate2(matches[0]));
                }
            }
            catch { foreach (var cert in store.Values.Distinct()) cert.Dispose(); throw; }
            finally { foreach (var cert in imported) cert.Dispose(); }
#else
            var info = Pkcs12Info.Decode(data, out int read);
            if (read != data.Length) throw new CryptographicException("Trailing PKCS#12 data");
            if (info.IntegrityMode != Pkcs12IntegrityMode.Password && info.IntegrityMode != Pkcs12IntegrityMode.None) throw new CryptographicException("Unsupported PKCS#12 integrity mode");
            X509Certificate2Collection imported = null;
            try
            {
                imported = X509CertificateLoader.LoadPkcs12Collection(data, pwd, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
                var bags = new List<Pkcs12SafeBag>();
                foreach (var contents in info.AuthenticatedSafe)
                {
                    if (contents.ConfidentialityMode == Pkcs12ConfidentialityMode.Password) contents.Decrypt(pwd);
                    if (contents.ConfidentialityMode != Pkcs12ConfidentialityMode.None) throw new CryptographicException("Unsupported PKCS#12 confidentiality mode");
                    CollectBags(contents, bags);
                }
                LoadBags(bags, imported);
            }
            catch { foreach (var cert in store.Values.Distinct()) cert.Dispose(); throw; }
            finally { if (imported != null) foreach (var cert in imported) cert.Dispose(); }
#endif
        }
#if !LEGACY_RUNTIME
        private static void CollectBags(Pkcs12SafeContents contents, List<Pkcs12SafeBag> bags)
        {
            foreach (var bag in contents.GetBags())
                if (bag is Pkcs12SafeContentsBag nested) CollectBags(nested.SafeContents, bags); else bags.Add(bag);
        }
        private static string BagAttribute(Pkcs12SafeBag bag, string oid)
        {
            var matches = bag.Attributes.Cast<CryptographicAttributeObject>().Where(a => a.Oid.Value == oid).ToArray();
            if (matches.Length == 0) return null;
            if (matches.Length != 1 || matches[0].Values.Count != 1) throw new CryptographicException("Ambiguous PKCS#12 attribute");
            var reader = new AsnReader(matches[0].Values[0].RawData, AsnEncodingRules.DER);
            string result = oid == "1.2.840.113549.1.9.20" ? reader.ReadCharacterString(UniversalTagNumber.BMPString) : RuntimeCompat.ToHexString(reader.ReadOctetString());
            reader.ThrowIfNotEmpty(); return result;
        }
        private void LoadBags(List<Pkcs12SafeBag> bags, X509Certificate2Collection imported)
        {
            const string friendly = "1.2.840.113549.1.9.20", localId = "1.2.840.113549.1.9.21";
            var certificates = bags.OfType<Pkcs12CertBag>().Where(b => b.IsX509Certificate).ToArray();
            // Key-bag aliases are independent of the friendly names on their certificate bags.
            foreach (var bag in bags.Where(b => b is Pkcs12KeyBag || b is Pkcs12ShroudedKeyBag))
            {
                string id = BagAttribute(bag, localId), alias = BagAttribute(bag, friendly);
                var certificateBag = id == null ? null : certificates.FirstOrDefault(c => BagAttribute(c, localId) == id);
                using var cert = certificateBag?.GetCertificate();
                var candidates = imported.Cast<X509Certificate2>().Where(c => c.HasPrivateKey && (cert == null || c.RawData.AsSpan().SequenceEqual(cert.RawData))).ToArray();
                if (candidates.Length != 1) throw new CryptographicException("Ambiguous or missing PKCS#12 key association");
                alias ??= id?.ToLowerInvariant() ?? RuntimeCompat.ToHexString(CryptoEncoding.SubjectKeyIdentifier(candidates[0])).ToLowerInvariant();
                SetCertificate(alias, new X509Certificate2(candidates[0]));
            }
            foreach (var bag in certificates)
            {
                string alias = BagAttribute(bag, friendly);
                if (alias == null || store.TryGetValue(alias, out var existing) && existing.HasPrivateKey) continue;
                SetCertificate(alias, bag.GetCertificate());
            }
        }
#endif
        private void SetCertificate(string alias, X509Certificate2 value)
        {
            if (store.TryGetValue(alias, out var previous)) previous.Dispose();
            store[alias] = value;
        }
        /// <summary>
        /// The aliases in the store.
        /// </summary>
        public ICollection<String> Keys
        {
            get
            {
                if (aliases == null) aliases = store.Keys.ToList();
                return aliases;
            }
        }

        /// <summary>
        /// The certificates in the store.
        /// </summary>
        public ICollection<X509Certificate2> Values
        {
            get
            {
                List<X509Certificate2> aliasList = new List<X509Certificate2>();
                foreach (String key in Keys)
                {
                    aliasList.Add(this[key]);
                }
                return aliasList;
            }
        }

        /// <summary>
        /// Access certificate using alias.
        /// </summary>
        /// <param name="key">The alias of the store entry</param>
        /// <returns>The certificate, optionally with key, of that alias</returns>
        /// <exception cref="KeyNotFoundException">The store doesn't contain the alias (key)</exception>
        /// <exception cref="NotSupportedException">The store is read only</exception>
        public X509Certificate2 this[String key]
        {
            get
            {
                if (key == null) new ArgumentNullException("key");

                if (TryGetValue(key, out X509Certificate2 cert))
                {
                    return cert;
                }
                else
                {
                    throw new KeyNotFoundException();
                }
            }
            set
            {
                throw new NotSupportedException("read only");
            }
        }

        /// <summary>
        /// Add entry to the store, not supported
        /// </summary>
        /// <param name="key">The alias</param>
        /// <param name="value">The certficate</param>
        /// <exception cref="NotSupportedException">Always thrown (read only)</exception>
        public void Add(string key, X509Certificate2 value)
        {
            throw new NotSupportedException("read only");
        }

        /// <summary>
        /// Check if the store contains the alias
        /// </summary>
        /// <param name="key">The alias to check</param>
        /// <returns>true if alias found, false otherwise</returns>
        /// <exception cref="ArgumentNullException">If the key is null</exception>
        public bool ContainsKey(string key)
        {
            if (key == null) throw new ArgumentNullException("key");

            return store.ContainsKey(key);
        }

        /// <summary>
        /// Remove an entry from the store, not supported
        /// </summary>
        /// <param name="key">The alias</param>
        /// <returns>true if removed, false if not found</returns>
        /// <exception cref="NotSupportedException">Always thrown (read only)</exception>
        public bool Remove(string key)
        {
            throw new NotSupportedException("read only");
        }

        /// <summary>
        /// Get the certficate with the provided alias of the store, safely.
        /// </summary>
        /// <param name="key">The alias</param>
        /// <param name="value">Placeholder for the certificate to be written, null if not found</param>
        /// <returns>true found, false if not found</returns>
        public bool TryGetValue(string key, out X509Certificate2 value)
        {
            if (key == null) new ArgumentNullException("key");

            if (store.ContainsKey(key))
            {
                value = GetAsDotNet(key);
                return true;
            }
            else
            {
                value = null;
                return false;
            }
        }

        /// <summary>
        /// Add certificate with the provided alias.
        /// </summary>
        /// <param name="item">The certificate to add</param>
        /// <exception cref="NotSupportedException">Always thrown (read only)</exception>
        public void Add(KeyValuePair<string, X509Certificate2> item)
        {
            throw new NotSupportedException("read only");
        }

        /// <summary>
        /// Clear all the entries from the store.
        /// </summary>
        /// <exception cref="NotSupportedException">Always thrown (read only)</exception>
        public void Clear()
        {
            throw new NotSupportedException("read only");
        }

        /// <summary>
        /// Verifies if certificate is present in the store with the same alias.
        /// </summary>
        /// <remarks>
        /// Uses thumbprint to verify if certificates are the same or not.
        /// </remarks>
        /// <param name="item">The alias to check and the certificate to compare with</param>
        /// <returns>true if same, false otherwise</returns>
        public bool Contains(KeyValuePair<string, X509Certificate2> item)
        {
            if (ContainsKey(item.Key))
            {
                X509Certificate2 cert = this[item.Key];
                if (cert == null || item.Value == null)
                {
                    return cert == null && item.Value == null;
                }
                else
                {
                    return cert.Thumbprint == item.Value.Thumbprint;
                }
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Copy the entries into the provided array at the requested index.
        /// </summary>
        /// <param name="array">The array to copy the entries too</param>
        /// <param name="arrayIndex">The starting index to copy too</param>
        /// <exception cref="ArgumentNullException">Array in null</exception>
        /// <exception cref="ArgumentOutOfRangeException">Array index is negative</exception>
        /// <exception cref="ArgumentException">The array is to small</exception>
        public void CopyTo(KeyValuePair<string, X509Certificate2>[] array, int arrayIndex)
        {
            if (array == null) throw new ArgumentNullException("array");
            if (arrayIndex < 0) throw new ArgumentOutOfRangeException("arrayIndex");
            if (array.Length - arrayIndex < Keys.Count) throw new ArgumentException("to small", "array");

            int i = arrayIndex;
            foreach (string key in Keys)
            {
                array[i++] = new KeyValuePair<string, X509Certificate2>(key, this[key]);
            }
        }

        /// <summary>
        /// Convert the dictionalry to a collection of certificates (with keys).
        /// </summary>
        /// <returns>X509Certificate2Collection of with all the certificates of the store</returns>
        public X509Certificate2Collection ToCollection()
        {
            X509Certificate2[] certs = new X509Certificate2[this.Count];
            this.Values.CopyTo(certs, 0);
            return new X509Certificate2Collection(certs);
        }

        /// <summary>
        /// Number of entries in the store
        /// </summary>
        public int Count
        {
            get
            {
                return store.Count;
            }
        }

        /// <summary>
        /// Always true, stores are read only.
        /// </summary>
        public bool IsReadOnly
        {
            get
            {
                return true;
            }
        }

        /// <summary>
        /// Remove an entry from the store.
        /// </summary>
        /// <param name="item">Entry to remove</param>
        /// <returns>true if removed, false otherwise</returns>
        /// <exception cref="NotSupportedException">Always thrown (read only)</exception>
        public bool Remove(KeyValuePair<string, X509Certificate2> item)
        {
            throw new NotSupportedException("read only");
        }

        /// <summary>
        /// Returns a clone of the store as enumerator of alias/certificate pairs.
        /// </summary>
        /// <returns>Enumerator of the alias/certificates pairs</returns>
        public IEnumerator<KeyValuePair<string, X509Certificate2>> GetEnumerator()
        {
            //TODO:make a real enumerator
            List<KeyValuePair<string, X509Certificate2>> aliasList = new List<KeyValuePair<string, X509Certificate2>>();
            foreach (String key in Keys)
            {
                aliasList.Add(new KeyValuePair<string, X509Certificate2>(key, this[key]));
            }
#if NET40
            return new SynchronizedReadOnlyCollection<KeyValuePair<string, X509Certificate2>>(aliasList).GetEnumerator();
#else
            return aliasList.GetEnumerator();
#endif
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>
        /// Install all the certificates in the correct store.
        /// </summary>
        /// <remarks>
        /// Installs the certificates with private keys in the "My" store.
        /// Installs the root certificates in the "Root" store, if not already present.
        /// Installs the intermediate certificates in the "CertificateAuthority" store, if not already present.
        /// </remarks>
        public void Install(StoreLocation location)
        {
            X509KeyStorageFlags flags = X509KeyStorageFlags.PersistKeySet
                | X509KeyStorageFlags.Exportable
                | (location == StoreLocation.CurrentUser ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.MachineKeySet);

            X509Store my = new X509Store(StoreName.My, location);
            my.Open(OpenFlags.ReadWrite);
            X509Store cas = new X509Store(StoreName.CertificateAuthority, location);
            cas.Open(OpenFlags.ReadWrite);
            X509Store root = new X509Store(StoreName.Root, location);
            root.Open(OpenFlags.ReadWrite);
            foreach (String key in Keys)
            {
                X509Certificate2 cert = GetAsDotNet(key, flags);
                if (cert.HasPrivateKey)
                {
                    my.Add(cert);
                }
                else
                {
                    X509BasicConstraintsExtension bcs = cert.Extensions.OfType<X509BasicConstraintsExtension>().Single();
                    if (!bcs.CertificateAuthority) continue; //we skip unneeded certificates;
                    if (cert.Issuer != cert.Subject)
                    {
                        if (!cas.Certificates.Contains(cert)) cas.Add(cert);
                    }
                    else
                    {
                        if (!root.Certificates.Contains(cert)) root.Add(cert);
                    }
                }
            }
            my.Close();
            cas.Close();
            root.Close();
        }

        private X509Certificate2 GetAsDotNet(string entryAlias)
        {
            return certs.GetOrAdd(entryAlias, alias => new Lazy<X509Certificate2>(() => GetAsDotNet(alias, X509KeyStorageFlags.Exportable))).Value;
        }

        /// <summary>
        /// Disposes the certificates (and their private keys) handed out by this store.
        /// </summary>
        public void Dispose()
        {
            foreach (var entry in certs.Values)
            {
                if (entry.IsValueCreated) entry.Value.Dispose();
            }
            certs.Clear();
            foreach (var cert in store.Values.Distinct()) cert.Dispose();
            store.Clear();
        }

        private X509Certificate2 GetAsDotNet(string entryAlias, X509KeyStorageFlags flags)
        {
            var cert = store[entryAlias];
            if ((flags & X509KeyStorageFlags.PersistKeySet) != 0 && cert.HasPrivateKey)
                return new X509Certificate2(cert.Export(X509ContentType.Pkcs12, password), password, flags);
            return new X509Certificate2(cert);
        }
    }
}
