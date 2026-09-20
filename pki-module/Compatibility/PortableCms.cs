#if LEGACY_RUNTIME
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using BContent = Org.BouncyCastle.Asn1.Cms.ContentInfo;
using ContentInfo = System.Security.Cryptography.Pkcs.ContentInfo;
using BSigner = Org.BouncyCastle.Asn1.Cms.SignerInfo;
using BAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;

namespace Egelke.EHealth.Client.Pki.Compatibility
{
    /// <summary>CMS metadata support for runtimes without the modern SignedCms editing APIs. Payload verification remains in the selected message backend.</summary>
    public sealed class PortableSignedCms
    {
        internal SignedData Structure { get; private set; }
        private readonly ContentInfo detachedContent;
        public bool Detached { get; }
        public PortableSignedCms() : this(new ContentInfo(Array.Empty<byte>()), false) { }
        public PortableSignedCms(ContentInfo content, bool detached = false) { detachedContent = content; Detached = detached; }
        public void Decode(byte[] encoded)
        {
            try
            {
                var content = BContent.GetInstance(Asn1Object.FromByteArray(encoded));
                if (content.ContentType.Id != CryptoEncoding.SignedData) throw new CryptographicException("Expected CMS SignedData");
                Structure = SignedData.GetInstance(content.Content);
            }
            catch (ArgumentException error) { throw new CryptographicException("Invalid CMS metadata", error); }
        }
        public byte[] Encode() => new BContent(CmsObjectIdentifiers.SignedData, Structure).GetEncoded("DER");
        public ContentInfo ContentInfo => new ContentInfo(new Oid(Structure.EncapContentInfo.ContentType.Id),
            Structure.EncapContentInfo.Content == null ? detachedContent.Content : Asn1OctetString.GetInstance(Structure.EncapContentInfo.Content).GetOctets());
        public X509Certificate2Collection Certificates
        {
            get
            {
                var certificates = new X509Certificate2Collection();
                if (Structure.Certificates != null)
                    foreach (Asn1Encodable value in Structure.Certificates)
                        if (value.ToAsn1Object() is Asn1Sequence) certificates.Add(CertificateCache.Load(value.GetEncoded("DER")));
                return certificates;
            }
        }
        public IReadOnlyList<PortableSignerInfo> SignerInfos => Enumerable.Range(0, Structure.SignerInfos.Count).Select(i => new PortableSignerInfo(this, i)).ToArray();
        public void AddCertificate(X509Certificate2 certificate)
        {
            var values = Structure.Certificates?.Cast<Asn1Encodable>().ToList() ?? new List<Asn1Encodable>();
            values.Add(Asn1Object.FromByteArray(certificate.RawData));
            Structure = new SignedData(Structure.DigestAlgorithms, Structure.EncapContentInfo, new DerSet(values.ToArray()), Structure.CRLs, Structure.SignerInfos);
        }
        public void RemoveCertificate(X509Certificate2 certificate)
        {
            var certificates = Structure.Certificates?.Cast<Asn1Encodable>().Where(c => !c.GetEncoded("DER").SequenceEqual(certificate.RawData)).ToArray();
            Structure = new SignedData(Structure.DigestAlgorithms, Structure.EncapContentInfo, certificates == null ? null : new DerSet(certificates), Structure.CRLs, Structure.SignerInfos);
        }
        public void CheckSignature(bool verifySignatureOnly)
        {
            if (SignerInfos.Count == 0) throw new CryptographicException("No CMS signer");
            var certificates = Certificates;
            try { foreach (var signer in SignerInfos) signer.CheckSignature(certificates, verifySignatureOnly); }
            finally { X509CertificateHelper.DisposeAll(certificates); }
        }
        internal void ReplaceSigner(int index, BSigner signer)
        {
            var signers = Structure.SignerInfos.Cast<Asn1Encodable>().ToArray(); signers[index] = signer;
            Structure = new SignedData(Structure.DigestAlgorithms, Structure.EncapContentInfo, Structure.Certificates, Structure.CRLs, new DerSet(signers));
        }
    }

    public sealed class PortableSubjectIdentifier
    {
        public SubjectIdentifierType Type { get; internal set; }
        public object Value { get; internal set; }
    }

    public sealed class PortableSignerInfo
    {
        private readonly PortableSignedCms parent;
        private readonly int index;
        private BSigner Value => BSigner.GetInstance(parent.Structure.SignerInfos[index]);
        internal PortableSignerInfo(PortableSignedCms parent, int index) { this.parent = parent; this.index = index; }
        public Oid DigestAlgorithm => new Oid(Value.DigestAlgorithm.Algorithm.Id);
        public Oid SignatureAlgorithm => new Oid(Value.SignatureAlgorithm.Algorithm.Id);
        public byte[] GetSignature() => Value.Signature.GetOctets();
        public PortableSubjectIdentifier SignerIdentifier
        {
            get
            {
                var id = Value.SignerID;
                if (id.IsTagged) return new PortableSubjectIdentifier { Type = SubjectIdentifierType.SubjectKeyIdentifier, Value = RuntimeCompat.ToHexString(Asn1OctetString.GetInstance(id.ID).GetOctets()) };
                var issuer = IssuerAndSerialNumber.GetInstance(id.ID);
                return new PortableSubjectIdentifier { Type = SubjectIdentifierType.IssuerAndSerialNumber,
                    Value = new X509IssuerSerial { IssuerName = new X500DistinguishedName(issuer.Name.GetEncoded("DER")).Name,
                        SerialNumber = RuntimeCompat.ToHexString(issuer.SerialNumber.Value.ToByteArrayUnsigned()) } };
            }
        }
        public CryptographicAttributeObjectCollection SignedAttributes => Attributes(Value.SignedAttrs);
        public CryptographicAttributeObjectCollection UnsignedAttributes => Attributes(Value.UnsignedAttrs);
        public IReadOnlyList<object> CounterSignerInfos => UnsignedAttributes.Cast<CryptographicAttributeObject>()
            .Where(a => a.Oid.Value == CmsAttributes.CounterSignature.Id).SelectMany(a => a.Values.Cast<object>()).ToArray();
        private static CryptographicAttributeObjectCollection Attributes(Asn1Set set)
        {
            var result = new CryptographicAttributeObjectCollection();
            if (set == null) return result;
            foreach (Asn1Encodable value in set)
            {
                var attribute = BAttribute.GetInstance(value); var oid = new Oid(attribute.AttrType.Id);
                var values = new AsnEncodedDataCollection();
                foreach (Asn1Encodable entry in attribute.AttrValues) values.Add(new AsnEncodedData(oid, entry.GetEncoded("DER")));
                result.Add(new CryptographicAttributeObject(oid, values));
            }
            return result;
        }
        public void AddUnsignedAttribute(AsnEncodedData value) => EditUnsigned(value, false);
        public void RemoveUnsignedAttribute(AsnEncodedData value) => EditUnsigned(value, true);
        private void EditUnsigned(AsnEncodedData value, bool remove)
        {
            var signer = Value;
            var attributes = signer.UnsignedAttrs?.Cast<Asn1Encodable>().Select(BAttribute.GetInstance).ToList() ?? new List<BAttribute>();
            var existing = attributes.Where(a => a.AttrType.Id == value.Oid.Value).ToArray();
            var values = existing.SelectMany(a => a.AttrValues.Cast<Asn1Encodable>()).ToList();
            foreach (var attribute in existing) attributes.Remove(attribute);
            if (remove) values.RemoveAll(v => v.GetEncoded("DER").SequenceEqual(value.RawData));
            else values.Add(Asn1Object.FromByteArray(value.RawData));
            if (values.Count != 0) attributes.Add(new BAttribute(new DerObjectIdentifier(value.Oid.Value), new DerSet(values.ToArray())));
            parent.ReplaceSigner(index, new BSigner(signer.SignerID, signer.DigestAlgorithm, signer.SignedAttrs, signer.SignatureAlgorithm,
                signer.Signature, attributes.Count == 0 ? null : new DerSet(attributes.Cast<Asn1Encodable>().ToArray())));
        }
        public void CheckSignature(X509Certificate2Collection certificates, bool verifySignatureOnly)
        {
            if (!verifySignatureOnly) throw new NotSupportedException("Use the eHealth certificate verifier for trust validation");
            var signed = new CmsSignedData(new CmsProcessableByteArray(parent.ContentInfo.Content), parent.Encode());
            var signer = signed.GetSignerInfos().GetSigners().Single();
            foreach (X509Certificate2 certificate in certificates)
            {
                var candidate = DotNetUtilities.FromX509Certificate(certificate);
                if (signer.SignerID.Match(candidate) && signer.Verify(candidate.GetPublicKey())) return;
            }
            throw new CryptographicException("Invalid CMS signature or missing signer certificate");
        }
    }
}
#endif
