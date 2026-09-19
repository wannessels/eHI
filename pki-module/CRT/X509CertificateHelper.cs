/*
 *  This file is part of eH-I.
 *  Copyright (C) 2014-2021 Egelke BVBA
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
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using BC = Org.BouncyCastle;
using BCX = Org.BouncyCastle.X509;
using BCA = Org.BouncyCastle.Asn1;
using BCAX = Org.BouncyCastle.Asn1.X509;
using BCAO = Org.BouncyCastle.Asn1.Ocsp;
using BCS = Org.BouncyCastle.X509.Store;
using System.Diagnostics;
using System.Runtime.InteropServices;
using BCO = Org.BouncyCastle.Ocsp;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.IO;
using Org.BouncyCastle.Security;
using System.Threading;
using System.Threading.Tasks;
using System.Collections;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;
using Org.BouncyCastle.Asn1.Oiw;

namespace Egelke.EHealth.Client.Pki
{

    internal class ValueWithRef<T, U>
    {
        public T Value { get; }

        public U Reference { get; }

        public ValueWithRef(T value, U reference)
        {
            this.Value = value;
            this.Reference = reference;
        }
    }

    /// <summary>
    /// Excention class for X509Certificate2.
    /// </summary>
    public static class X509CertificateHelper
    {
        //private const int CRYPT_E_EXISTS = unchecked((int)0x80092005);

        private static readonly TimeSpan ClockSkewness = new TimeSpan(0, 5, 0);
        private static readonly TraceSource trace = new TraceSource("Egelke.EHealth.Tsa");
        private static readonly HttpClient http = new HttpClient() { Timeout = Timeout.InfiniteTimeSpan };
        private static readonly AsyncSingleFlight<string, BCAO.OcspResponse> ocspDownloads = new AsyncSingleFlight<string, BCAO.OcspResponse>();
        private static readonly AsyncSingleFlight<string, BCAX.CertificateList> crlDownloads = new AsyncSingleFlight<string, BCAX.CertificateList>();

        /// <summary>
        /// Maximum time to wait for a single OCSP responder, defaults to 5 seconds.
        /// </summary>
        public static TimeSpan OcspTimeout { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>
        /// Maximum time to wait for a single CRL download, defaults to 30 seconds.
        /// </summary>
        public static TimeSpan CrlTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Maximum time the platform chain builder may spend downloading a missing intermediate, defaults to 5 seconds.
        /// </summary>
        public static TimeSpan UrlRetrievalTimeout { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>
        /// Never let the platform chain builder download missing intermediates (.NET 5+ only), defaults to <c>false</c>.
        /// </summary>
        /// <remarks>
        /// Enable on servers where all intermediates are provided via the extra store.
        /// </remarks>
        public static bool DisableCertificateDownloads { get; set; } = false;

        /// <summary>
        /// Wrapper of the X509Chain, just for compatbility
        /// </summary>
        /// <param name="cert">The certificate to validate</param>
        /// <param name="validationTime">The time upon wich the validate</param>
        /// <param name="extraStore">Extra certs to use when creating the chain</param>
        /// <returns></returns>
        public static Chain BuildChain(this X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore)
        {
            DateTime now = DateTime.UtcNow;
            if (validationTime > (now + ClockSkewness))
            {
                throw new ArgumentException("validation can't occur in the future", "validationTime");
            }

            using (X509Chain x509Chain = new X509Chain())
            {
                if (extraStore != null) x509Chain.ChainPolicy.ExtraStore.AddRange(extraStore);
                x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                x509Chain.ChainPolicy.VerificationTime = validationTime;
                x509Chain.ChainPolicy.UrlRetrievalTimeout = UrlRetrievalTimeout;
#if NET5_0_OR_GREATER
                x509Chain.ChainPolicy.DisableCertificateDownloads = DisableCertificateDownloads;
#endif
                x509Chain.Build(cert);

                Chain chain = new Chain();
                foreach (var status in x509Chain.ChainStatus)
                {
                    trace.TraceEvent(status.Status != X509ChainStatusFlags.NoError ? TraceEventType.Warning : TraceEventType.Information, 0,
                        "The certificate chain for {0} has a status {1}: {2}", cert.Subject, status.Status, status.StatusInformation);
                    chain.ChainStatus.Add(status);
                }

                foreach (X509ChainElement x509Element in x509Chain.ChainElements)
                {
                    chain.ChainElements.Add(new ChainElement(x509Element));
                }

                return chain;
            }
        }

        /// <summary>
        /// Dispose every certificate in the collection and empty it.
        /// </summary>
        /// <param name="certs">Collection of certificates that are owned by the caller</param>
        public static void DisposeAll(X509Certificate2Collection certs)
        {
            foreach (X509Certificate2 cert in certs) cert.Dispose();
            certs.Clear();
        }

        /// <summary>
        /// Build a chain for the certificates and verifies the revocation (own implementation)
        /// </summary>
        /// <param name="cert">The certificate to validate</param>
        /// <param name="validationTime">The time upon wich the validate</param>
        /// <param name="extraStore">Extra certs to use when creating the chain</param>
        /// <param name="crls">Already known crl's, newly retrieved CRL's will be added here</param>
        /// <param name="ocsps">Already konwn ocsp's, newly retreived OCSP's will be added here</param>
        /// <returns>The chain with all the information about validity</returns>
        public static Chain BuildChain(this X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore, IList<BCAX.CertificateList> crls, IList<BCAO.BasicOcspResponse> ocsps)
        {
            return cert.BuildChainAsync(validationTime, extraStore, crls, ocsps).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Build a chain for the certificates and verifies the revocation (own implementation)
        /// </summary>
        /// <param name="cert">The certificate to validate</param>
        /// <param name="validationTime">The time upon wich the validate</param>
        /// <param name="extraStore">Extra certs to use when creating the chain</param>
        /// <param name="crls">Already known crl's, newly retrieved CRL's will be added here</param>
        /// <param name="ocsps">Already konwn ocsp's, newly retreived OCSP's will be added here</param>
        /// <returns>The chain with all the information about validity</returns>
        public static async Task<Chain> BuildChainAsync(this X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore, IList<BCAX.CertificateList> crls, IList<BCAO.BasicOcspResponse> ocsps)
        {
            Chain chain = cert.BuildChain(validationTime, extraStore);

            if (cert.IsOcspNoCheck())
                return chain; //nothing to do

            for (int i = 0; i < (chain.ChainElements.Count - 1); i++)
            {
                X509Certificate2 nextCert = chain.ChainElements[i].Certificate;
                X509Certificate2 nextIssuer = chain.ChainElements[i + 1].Certificate;

                try
                {
                    BCAO.BasicOcspResponse ocspResponse = null;
                    try
                    {
                        ocspResponse = nextCert.Verify(nextIssuer, validationTime, ocsps);
                        if (ocspResponse == null && RevocationCache.TryGetOcsp(nextCert, nextIssuer, out BCAO.BasicOcspResponse cachedOcsp))
                        {
                            ocsps.Add(cachedOcsp);
                            ocspResponse = nextCert.Verify(nextIssuer, validationTime, ocsps);
                        }
                        if (ocspResponse == null)
                        {
                            // Fresh local evidence is sufficient; do not wait for a failing responder first.
                            if (VerifyAvailableCrl(nextCert, nextIssuer, validationTime, crls)) continue;
                            BCAO.OcspResponse ocspMsg = await nextCert.GetOcspResponseAsync(nextIssuer).ConfigureAwait(false);
                            if (ocspMsg != null)
                            {
                                var downloaded = BCAO.BasicOcspResponse.GetInstance(BCA.Asn1Object.FromByteArray(ocspMsg.ResponseBytes.Response.GetOctets()));
                                ocsps.Add(downloaded);
                                ocspResponse = nextCert.Verify(nextIssuer, validationTime, ocsps);
                                if (ocspResponse != null) RevocationCache.PutOcsp(nextCert, nextIssuer, ocspResponse);
                            }
                        }
                    }
                    catch (RevocationException<BCAO.BasicOcspResponse>)
                    {
                        throw;
                    }
                    catch (RevocationException<BCAX.CertificateList>)
                    {
                        throw;
                    }
                    catch (Exception e)
                    {
                        ocspResponse = null;
                        trace.TraceEvent(TraceEventType.Warning, 0, "OCSP validation of {0} failed, falling back to CRL: {1}", nextCert.Subject, e.Message);
                    }

                    if (ocspResponse == null)
                    {
                        BCAX.CertificateList crl = nextCert.Verify(nextIssuer, validationTime, crls);
                        if (crl == null && RevocationCache.TryGetCrl(nextCert, nextIssuer, out BCAX.CertificateList cachedCrl))
                        {
                            crls.Add(cachedCrl);
                            crl = nextCert.Verify(nextIssuer, validationTime, crls);
                        }
                        if (crl == null)
                        {
                            crl = await nextCert.GetCertificateListAsync().ConfigureAwait(false);
                            if (crl != null)
                            {
                                crls.Add(crl);
                                crl = nextCert.Verify(nextIssuer, validationTime, crls);
                                if (crl != null) RevocationCache.PutCrl(nextCert, nextIssuer, crl);
                            }
                        }
                        if (crl == null) throw new RevocationUnknownException("No applicable revocation evidence was found");
                    }
                }
                catch (RevocationException<BCAO.BasicOcspResponse> revoked)
                {
                    RevocationCache.PutOcsp(nextCert, nextIssuer, revoked.RevocationInfo);
                    AddErrorStatus(chain.ChainStatus, chain.ChainElements[i].ChainElementStatus, X509ChainStatusFlags.Revoked, "The certificate has been revoked");
                }
                catch (RevocationException<BCAX.CertificateList> revoked)
                {
                    RevocationCache.PutCrl(nextCert, nextIssuer, revoked.RevocationInfo);
                    AddErrorStatus(chain.ChainStatus, chain.ChainElements[i].ChainElementStatus, X509ChainStatusFlags.Revoked, "The certificate has been revoked");
                }
                catch
                {
                    AddErrorStatus(chain.ChainStatus, chain.ChainElements[i].ChainElementStatus, X509ChainStatusFlags.RevocationStatusUnknown, "Invalid OCSP/CRL found");
                }
            }
            return chain;
        }

        private static bool VerifyAvailableCrl(X509Certificate2 cert, X509Certificate2 issuer, DateTime time, IList<BCAX.CertificateList> crls)
        {
            try
            {
                if (cert.Verify(issuer, time, crls) != null) return true;
                if (!RevocationCache.TryGetCrl(cert, issuer, out var cached)) return false;
                crls.Add(cached);
                return cert.Verify(issuer, time, crls) != null;
            }
            catch (RevocationException<BCAX.CertificateList>) { throw; }
            catch (Exception error)
            {
                trace.TraceEvent(TraceEventType.Warning, 0, "Cached CRL cannot establish status: {0}", error.Message);
                return false;
            }
        }
        /// <summary>
        /// Is the OCSP NoCheck extention present?
        /// </summary>
        /// <param name="certificate">The cert to check</param>
        /// <returns><c>true</c>When present, <c>false</c>otherwise</returns>
        public static bool IsOcspNoCheck(this X509Certificate2 certificate)
        {
            return certificate.Extensions[BCAO.OcspObjectIdentifiers.PkixOcspNocheck.Id] != null;
        }

        /// <summary>
        /// Validates the cert with the provided ocsp responses.
        /// </summary>
        /// <param name="certificate">The cert to validate</param>
        /// <param name="issuer">The issuer of the cert to validate</param>
        /// <param name="validationTime">The time on which the cert was needed to validated</param>
        /// <param name="ocspResponses">The list of ocsp responses to use</param>
        /// <returns>The OCSP response that was used, <c>null</c> if none was found</returns>
        /// <exception cref="RevocationException{T}">When the certificate was revoked on the provided time</exception>
        /// <exception cref="RevocationUnknownException">When the certificate (or the OCSP) can't be validated</exception>
        public static BCAO.BasicOcspResponse Verify(this X509Certificate2 certificate, X509Certificate2 issuer, DateTime validationTime, IList<BCAO.BasicOcspResponse> ocspResponses)
        {
            DateTime minTime = validationTime - ClockSkewness;
            DateTime maxTime = validationTime + ClockSkewness;
            BCX.X509Certificate certificateBC = DotNetUtilities.FromX509Certificate(certificate);
            BCX.X509Certificate issuerBC = DotNetUtilities.FromX509Certificate(issuer);

            ValueWithRef<BCO.SingleResp, ValueWithRef<BCO.BasicOcspResp, BCAO.BasicOcspResponse>> singleOcspRespLeaf = ocspResponses
                .Select((rsp) => new ValueWithRef<BCO.BasicOcspResp, BCAO.BasicOcspResponse>(new BCO.BasicOcspResp(rsp), rsp)) //convert, but keep the original
                .SelectMany((r) => r.Value.Responses.Select(sr => new ValueWithRef<BCO.SingleResp, ValueWithRef<BCO.BasicOcspResp, BCAO.BasicOcspResponse>>(sr, r))) //get the single respononses, but keep the parent
                .Where((sr) => sr.Value.GetCertID().SerialNumber.Equals(certificateBC.SerialNumber) && sr.Value.GetCertID().MatchesIssuer(issuerBC)) //is it for this cert?
                .Where((sr) => sr.Value.ThisUpdate >= minTime || (sr.Value.NextUpdate != null && sr.Value.NextUpdate.Value >= minTime)) //was it issued on time?
                .OrderByDescending((sr) => sr.Value.ThisUpdate) //newest first
                .FirstOrDefault();

            if (singleOcspRespLeaf == null)
                return null;

            BCO.SingleResp singleOcspResp = singleOcspRespLeaf.Value;
            BCO.BasicOcspResp basicOcspResp = singleOcspRespLeaf.Reference.Value;
            BCAO.BasicOcspResponse basicOcspResponse = singleOcspRespLeaf.Reference.Reference;

            //get the signer name
            BCX.X509Certificate ocspSignerBc;
            BCAX.X509Name responderName = basicOcspResp.ResponderId.ToAsn1Object().Name;
            byte[] keyHash = basicOcspResp.ResponderId.ToAsn1Object().GetKeyHash();
            if (responderName != null)
            {
                //Get the signer certificate via name
                var selector = new BCS.X509CertStoreSelector
                {
                    Subject = responderName
                };
                ocspSignerBc = basicOcspResp
                    .GetCertificates()
                    .EnumerateMatches(selector)
                    .Cast<BCX.X509Certificate>()
                    .FirstOrDefault();
            } 
            else if (keyHash != null)
            {
                //Get the signer certificate via key hash
                using (var sha1 = SHA1.Create())
                {
                    ocspSignerBc = basicOcspResp
                        .GetCertificates()
                        .EnumerateMatches(null)
                        .Cast<BCX.X509Certificate>()
                        .Where(c => {
                            byte[] certKey = c.CertificateStructure.SubjectPublicKeyInfo.PublicKey.GetBytes();
                            byte[] certkeyHash = sha1.ComputeHash(certKey);
                            return Enumerable.SequenceEqual(certkeyHash, keyHash);
                        })
                        .FirstOrDefault();
                }
            }
            else
            { 
                trace.TraceEvent(TraceEventType.Error, 0, "OCSP response for {0} does not have a ResponderID", certificate.Subject);
                throw new RevocationUnknownException("OCSP response for {0} does not have a ResponderID");
            }

            if (ocspSignerBc == null)
                throw new RevocationUnknownException("The OCSP is signed by a unknown certificate");

            //verify the response signature
            if (!basicOcspResp.Verify(ocspSignerBc.GetPublicKey()))
                throw new RevocationUnknownException("The OCSP has an invalid signature");


            //OCSP must be issued by same issuer an the certificate that it validates.
            try
            {
                if (!ocspSignerBc.IssuerDN.Equals(issuerBC.SubjectDN)) throw new ApplicationException();
                ocspSignerBc.Verify(issuerBC.GetPublicKey());
            }
            catch (Exception e)
            {
                throw new RevocationUnknownException("The OCSP signer was not issued by the proper CA", e);
            }

            //verify if the OCSP signer certificate is stil valid
            if (!ocspSignerBc.IsValid(basicOcspResp.ProducedAt))
                throw new RevocationUnknownException("The OCSP signer was not valid at the time the ocsp was issued");


            //check if the signer may issue OCSP
            IList<DerObjectIdentifier> ocspSignerExtKeyUsage = ocspSignerBc.GetExtendedKeyUsage();
            if (!ocspSignerExtKeyUsage.Contains(KeyPurposeID.id_kp_OCSPSigning)) // 1.3.6.1.5.5.7.3.9
                throw new RevocationUnknownException("The OCSP is signed by a certificate that isn't allowed to sign OCSP");

            //finally, check if the certificate is revoked or not
            var revokedStatus = (BCO.RevokedStatus)singleOcspResp.GetCertStatus();
            if (revokedStatus != null)
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "OCSP response for {0} indicates that the certificate is revoked on {1}", certificate.Subject, revokedStatus.RevocationTime);
                if (maxTime >= revokedStatus.RevocationTime)
                    throw new RevocationException<BCAO.BasicOcspResponse>(basicOcspResponse, "The certificate was revoked on " + revokedStatus.RevocationTime.ToString("o"));
            }

            return basicOcspResponse;
        }

        /// <summary>
        /// Validates the cert with the provided crl responses.
        /// </summary>
        /// <param name="certificate">The cert to validate</param>
        /// <param name="issuer">The issuer of the cert to validate</param>
        /// <param name="validationTime">The time on which the cert was needed to validated</param>
        /// <param name="certLists">The list of crls  to use</param>
        /// <returns>The crl response that was used, <c>null</c> if none used</returns>
        /// <exception cref="RevocationException{T}">When the certificate was revoked on the provided time</exception>
        /// <exception cref="RevocationUnknownException">When the certificate (or the crl) can't be validated</exception>
        public static BCAX.CertificateList Verify(this X509Certificate2 certificate, X509Certificate2 issuer, DateTime validationTime, IList<BCAX.CertificateList> certLists)
        {
            DateTime minTime = validationTime - ClockSkewness;
            DateTime maxTime = validationTime + ClockSkewness;
            BCX.X509Certificate certificateBC = DotNetUtilities.FromX509Certificate(certificate);
            BCX.X509Certificate issuerBC = DotNetUtilities.FromX509Certificate(issuer);

            ValueWithRef<ParsedCrl, BCAX.CertificateList> crlWithOrg = certLists
                .Select((c) => new ValueWithRef<ParsedCrl, BCAX.CertificateList>(ParsedCrl.Get(c), c)) //convert, keep orginal
                .Where((c) => c.Value.Crl.IssuerDN.Equals(certificateBC.IssuerDN))
                .Where((c) => IsApplicableCrl(certificateBC, c.Value.Crl))
                .Where((c) => c.Value.Crl.ThisUpdate >= minTime || (c.Value.Crl.NextUpdate != null && c.Value.Crl.NextUpdate.Value >= minTime))
                .OrderByDescending((c) => c.Value.Crl.ThisUpdate)
                .FirstOrDefault();

            if (crlWithOrg == null)
                return null;

            ParsedCrl crl = crlWithOrg.Value;
            BCAX.CertificateList certList = crlWithOrg.Reference;

            //check the signature (no need the check the issuer here)
            try
            {
                crl.Verify(issuerBC.GetPublicKey());
            }
            catch (Exception e)
            {
                throw new RevocationUnknownException("The CRL has an invalid signature", e);
            }

            //check the signer (only the part relevant for CRL)
            if (!issuerBC.GetKeyUsage()[6])
            {
                throw new RevocationUnknownException("The CRL was signed with a certificate that isn't allowed to sign CRLs");
            }

            //check if the certificate is revoked
            BCX.X509CrlEntry crlEntry = crl.GetRevokedCertificate(certificateBC.SerialNumber);
            if (crlEntry != null)
            {
                trace.TraceEvent(TraceEventType.Verbose, 0, "CRL indicates that {0} is revoked on {1}", certificate.Subject, crlEntry.RevocationDate);
                if (maxTime >= crlEntry.RevocationDate)
                {
                    throw new RevocationException<BCAX.CertificateList>(certList, "The certificate was revoked on " + crlEntry.RevocationDate.ToString("o"));
                }
            }

            return certList;
        }

        private static bool IsApplicableCrl(BCX.X509Certificate cert, BCX.X509Crl crl)
        {
            // Delta, indirect and reason-partitioned CRLs require evidence-combination logic we do not implement.
            if (crl.GetExtensionValue(BCAX.X509Extensions.DeltaCrlIndicator) != null) return false;
            var extension = crl.GetExtensionValue(BCAX.X509Extensions.IssuingDistributionPoint);
            if (extension == null) return true;
            var scope = BCAX.IssuingDistributionPoint.GetInstance(extension.GetOctets());
            if (scope.IsIndirectCrl || scope.OnlyContainsAttributeCerts || scope.OnlySomeReasons != null) return false;
            bool isCa = cert.GetBasicConstraints() >= 0;
            if (scope.OnlyContainsCACerts && !isCa || scope.OnlyContainsUserCerts && isCa) return false;
            if (scope.DistributionPoint == null) return true;
            var pointsExtension = cert.GetExtensionValue(BCAX.X509Extensions.CrlDistributionPoints);
            if (pointsExtension == null) return false;
            var points = BCAX.CrlDistPoint.GetInstance(pointsExtension.GetOctets()).GetDistributionPoints();
            return points.Any(point => point.CrlIssuer == null && point.Reasons == null &&
                point.DistributionPointName != null && point.DistributionPointName.Equals(scope.DistributionPoint));
        }


        /// <summary>
        /// Gets the OCSP response from the server.
        /// </summary>
        /// <remarks>
        /// Never returns an exception.
        /// </remarks>
        /// <param name="cert">The certificate to get the server info from</param>
        /// <param name="issuer">The issue certificate of the certificate to get the server info from</param>
        /// <returns>The OCSP response (parsed) or <c>null</c> when none found</returns>
        /// <exception cref="RevocationUnknownException">When the revocation info can be retreived</exception>
        public static BCAO.OcspResponse GetOcspResponse(this X509Certificate2 cert, X509Certificate2 issuer)
        {
            return cert.GetOcspResponseAsync(issuer).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Gets the OCSP response from the server.
        /// </summary>
        /// <remarks>
        /// Never returns an exception.
        /// </remarks>
        /// <param name="cert">The certificate to get the server info from</param>
        /// <param name="issuer">The issue certificate of the certificate to get the server info from</param>
        /// <returns>The OCSP response (parsed) or <c>null</c> when none found</returns>
        /// <exception cref="RevocationUnknownException">When the revocation info can be retreived</exception>
        public static async Task<BCAO.OcspResponse> GetOcspResponseAsync(this X509Certificate2 cert, X509Certificate2 issuer)
        {
            Exception lastException = null;
            byte[] ocspReqBytes = null;
            foreach (Uri uri in cert.GetOCSPUris())
            {
                try
                {
                    if (ocspReqBytes == null) ocspReqBytes = cert.GetOcspReqBody(issuer).GetEncoded();

                    byte[] request = ocspReqBytes;
                    return await ocspDownloads.RunAsync(uri.AbsoluteUri + "|" + issuer.Thumbprint + "|" + cert.SerialNumber,
                        () => DownloadOcspAsync(uri, request)).ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    lastException = e;
                    trace.TraceEvent(TraceEventType.Warning, 0, "Failed to manually obtain ocsp: {0}", e);
                }
            }
            if (lastException != null) throw lastException;
            return null;
        }

        private static async Task<BCAO.OcspResponse> DownloadOcspAsync(Uri uri, byte[] request)
        {
            using (var cts = new CancellationTokenSource(OcspTimeout))
            using (var content = new ByteArrayContent(request))
            {
                content.Headers.ContentType = new MediaTypeHeaderValue("application/ocsp-request");
                using (var response = await http.PostAsync(uri, content, cts.Token).ConfigureAwait(false))
                {
                    VerifyOCSPRsp(response);
                    return ParseOCSPResponse(await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false));
                }
            }
        }

        private static BCO.OcspReq GetOcspReqBody(this X509Certificate2 cert, X509Certificate2 issuer)
        {
            var ocspReqGen = new BCO.OcspReqGenerator();
            ocspReqGen.AddRequest(
                new BCO.CertificateID(
                    new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1),
                    DotNetUtilities.FromX509Certificate(issuer),
                    DotNetUtilities.FromX509Certificate(cert).SerialNumber));
            return ocspReqGen.Generate();
        }

        private static BCAO.OcspResponse ParseOCSPResponse(byte[] ocspRspBytes)
        {
            BCAO.OcspResponse ocspResponse = BCAO.OcspResponse.GetInstance(BCA.Asn1Sequence.FromByteArray(ocspRspBytes));
            if (ocspResponse.ResponseStatus.IntValueExact != BCAO.OcspResponseStatus.Successful)
            {
                throw new RevocationUnknownException("OCSP Response with invalid status: " + ocspResponse.ResponseStatus.IntValueExact);
            }
            return ocspResponse;
        }

        private static IEnumerable<Uri> GetOCSPUris(this X509Certificate2 cert)
        {
            X509Extension crlExtention = cert.Extensions[BCAX.X509Extensions.AuthorityInfoAccess.Id];
            if (crlExtention == null)
                return Enumerable.Empty<Uri>();

            var aia = BCAX.AuthorityInformationAccess.GetInstance(BCA.Asn1Sequence.FromByteArray(crlExtention.RawData));
            return aia.GetAccessDescriptions()
                .Where((ad) => ad.AccessMethod.Id == BCAX.AccessDescription.IdADOcsp.Id)
                .Select((ad) => ad.AccessLocation)
                .Where((gn) => gn.TagNo == BCAX.GeneralName.UniformResourceIdentifier && gn.Name is BCA.DerStringBase)
                .Select((gn) => new Uri(((BCA.DerStringBase)gn.Name).GetString()))
                .Where((u) => u.Scheme == "http" || u.Scheme == "https");
        }

        private static void VerifyOCSPRsp(HttpResponseMessage webRsp)
        {
            if (webRsp.StatusCode != HttpStatusCode.OK
                || webRsp.Content?.Headers.ContentType?.MediaType != "application/ocsp-response")
            {
                trace.TraceEvent(TraceEventType.Error, 0, "Invalid http status or contentype for ocsp response: {0}", webRsp.ReasonPhrase);
                throw new RevocationUnknownException("Response with invalid status or contenttype for ocsp response: " + webRsp.ReasonPhrase);
            }
        }

        /// <summary>
        /// Download the crl from the server
        /// </summary>
        /// <param name="cert">the certificat to get the server info from</param>
        /// <returns>The clr (parsed) or <c>null</c> when none found</returns>
        /// <exception cref="RevocationUnknownException">When the revocation info can be retreived</exception>
        public static BCAX.CertificateList GetCertificateList(this X509Certificate2 cert)
        {
            return cert.GetCertificateListAsync().ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Download the crl from the server
        /// </summary>
        /// <param name="cert">the certificat to tge the server info from</param>
        /// <returns>The clr (parsed) or <c>null</c> when none found</returns>
        /// <exception cref="RevocationUnknownException">When the revocation info can be retreived</exception>
        public static async Task<BCAX.CertificateList> GetCertificateListAsync(this X509Certificate2 cert)
        {
            Exception lastException = null;
            foreach (Uri uri in cert.GetCrlWebUris())
            {
                try
                {
                    return await crlDownloads.RunAsync(uri.AbsoluteUri, () => DownloadCrlAsync(uri)).ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    lastException = e;
                    trace.TraceEvent(TraceEventType.Warning, 0, "Failed to manually obtain crl: {0}", e);
                }
            }
            if (lastException != null) throw lastException;
            return null;
        }

        private static async Task<BCAX.CertificateList> DownloadCrlAsync(Uri uri)
        {
            using (var cts = new CancellationTokenSource(CrlTimeout))
            using (var response = await http.GetAsync(uri, cts.Token).ConfigureAwait(false))
            {
                VerifyCrlRsp(response);
                var body = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                return BCAX.CertificateList.GetInstance(BCA.Asn1Sequence.FromByteArray(body));
            }
        }

        private static void VerifyCrlRsp(HttpResponseMessage webRsp)
        {
            if (webRsp.StatusCode != HttpStatusCode.OK)
            {
                trace.TraceEvent(TraceEventType.Error, 0, "Invalid http status for crl reply: {0}", webRsp.ReasonPhrase);
                throw new RevocationUnknownException("Response with invalid status the crl reply: " + webRsp.ReasonPhrase);
            }
        }

        private static IEnumerable<Uri> GetCrlWebUris(this X509Certificate2 cert)
        {
            X509Extension crlExtention = cert.Extensions[BCAX.X509Extensions.CrlDistributionPoints.Id];
            if (crlExtention == null)
                return Enumerable.Empty<Uri>();

            var distributionPoint = BCAX.CrlDistPoint.GetInstance(BCA.Asn1Sequence.FromByteArray(crlExtention.RawData));
            return distributionPoint.GetDistributionPoints()
                .Select((dp) => dp.DistributionPointName.Name)
                .Cast<BCAX.GeneralNames>()
                .SelectMany((gns) => gns.GetNames())
                .Where((gn) => gn.TagNo == BCAX.GeneralName.UniformResourceIdentifier && gn.Name is BCA.DerStringBase)
                .Select((gn) => new Uri(((BCA.DerStringBase)gn.Name).GetString()))
                .Where((u) => u.Scheme == "http" || u.Scheme == "https");
        }


        internal static void AddErrorStatus(List<X509ChainStatus> chainStatus, List<X509ChainStatus> elementStatus, X509ChainStatusFlags extraStatusFlag, String extraStatusInfo)
        {
            X509ChainStatus extraStatus = new X509ChainStatus
            {
                Status = extraStatusFlag,
                StatusInformation = extraStatusInfo
            };
            if (chainStatus != null) AddErrorStatus(chainStatus, extraStatus);
            if (elementStatus != null) AddErrorStatus(elementStatus, extraStatus);
        }

        private static void AddErrorStatus(List<X509ChainStatus> status, X509ChainStatus extraStatus)
        {
            status.RemoveAll(x => x.Status == X509ChainStatusFlags.NoError);
            if (!status.Any(x => x.Status == extraStatus.Status)) status.Add(extraStatus);
        }
    }
}
