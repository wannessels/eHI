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
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Collections;
using System.Security.Cryptography;
using X509Extension = System.Security.Cryptography.X509Certificates.X509Extension;

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
        private static readonly AsyncSingleFlight<string, OcspResponse> ocspDownloads = new AsyncSingleFlight<string, OcspResponse>();
        private static readonly AsyncSingleFlight<string, CertificateRevocationList> crlDownloads = new AsyncSingleFlight<string, CertificateRevocationList>();

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
        public static bool DisableCertificateDownloads { get => disableCertificateDownloads; set { disableCertificateDownloads = value; ChainCache.Clear(); } }
        private static bool disableCertificateDownloads;

        /// <summary>Optional explicit trust anchors. Null uses the operating-system trust store. Configure before serving requests.</summary>
        public static X509Certificate2Collection CustomTrustStore { get => customTrustStore; set { customTrustStore = value; ChainCache.Clear(); } }
        private static X509Certificate2Collection customTrustStore;

        /// <summary>
        /// Wrapper of the X509Chain, just for compatbility
        /// </summary>
        /// <param name="cert">The certificate to validate</param>
        /// <param name="validationTime">The time upon wich the validate</param>
        /// <param name="extraStore">Extra certs to use when creating the chain</param>
        /// <returns></returns>
        public static Chain BuildChain(this X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore)
        {
            OperationScope.Cancellation.ThrowIfCancellationRequested();
            DateTime now = DateTime.UtcNow;
            if (validationTime > (now + ClockSkewness))
            {
                throw new ArgumentException("validation can't occur in the future", "validationTime");
            }

            string key = ChainCache.Key(cert, extraStore);
            Chain cached = ChainCache.TryGet(key, validationTime);
            if (cached != null) { EHealthMetrics.ChainBuilds.Add(1, new TagList { { "source", "cache" } }); return cached; }
            long started = Stopwatch.GetTimestamp();
            using (X509Chain x509Chain = new X509Chain())
            {
                if (extraStore != null) x509Chain.ChainPolicy.ExtraStore.AddRange(extraStore);
                x509Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                if (CustomTrustStore != null)
                {
                    x509Chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    x509Chain.ChainPolicy.CustomTrustStore.AddRange(CustomTrustStore);
                }
                x509Chain.ChainPolicy.VerificationTime = validationTime;
                x509Chain.ChainPolicy.UrlRetrievalTimeout = OperationScope.LimitTimeout(UrlRetrievalTimeout);
#if NET5_0_OR_GREATER
                x509Chain.ChainPolicy.DisableCertificateDownloads = DisableCertificateDownloads;
#endif
                x509Chain.Build(cert);
                EHealthMetrics.Record(EHealthMetrics.ChainBuilds, EHealthMetrics.ChainBuildDuration, started, new TagList { { "source", "platform" } });
                OperationScope.Cancellation.ThrowIfCancellationRequested();

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
                ChainCache.Put(key, chain);
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
        public static Chain BuildChain(this X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps)
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
        public static Task<Chain> BuildChainAsync(this X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps)
            => BuildChainAsync(cert, validationTime, extraStore, crls, ocsps, CancellationToken.None);

        /// <summary>Builds and validates a chain under the shared admission/deadline policy.</summary>
        public static Task<Chain> BuildChainAsync(this X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps, CancellationToken cancellationToken)
            => OperationPolicy.Default.RunAsync("chain", _ => BuildChainCoreAsync(cert, validationTime, extraStore, crls, ocsps), cancellationToken);

        private static async Task<Chain> BuildChainCoreAsync(X509Certificate2 cert, DateTime validationTime, X509Certificate2Collection extraStore, IList<CertificateRevocationList> crls, IList<OcspResponse> ocsps)
        {
            Chain chain = cert.BuildChain(validationTime, extraStore);

            if (cert.IsOcspNoCheck())
                return chain; //nothing to do

            for (int i = 0; i < (chain.ChainElements.Count - 1); i++)
            {
                OperationScope.Cancellation.ThrowIfCancellationRequested();
                X509Certificate2 nextCert = chain.ChainElements[i].Certificate;
                X509Certificate2 nextIssuer = chain.ChainElements[i + 1].Certificate;

                try
                {
                    OcspResponse ocspResponse = null;
                    try
                    {
                        ocspResponse = nextCert.Verify(nextIssuer, validationTime, ocsps);
                        if (ocspResponse == null && RevocationCache.TryGetOcsp(nextCert, nextIssuer, out OcspResponse cachedOcsp))
                        {
                            ocsps.Add(cachedOcsp);
                            ocspResponse = nextCert.Verify(nextIssuer, validationTime, ocsps);
                        }
                        if (ocspResponse == null)
                        {
                            // Fresh local evidence is sufficient; do not wait for a failing responder first.
                            if (VerifyAvailableCrl(nextCert, nextIssuer, validationTime, crls)) continue;
                            OcspResponse ocspMsg = await nextCert.GetOcspResponseAsync(nextIssuer).ConfigureAwait(false);
                            if (ocspMsg != null)
                            {
                                var downloaded = ocspMsg;
                                ocsps.Add(downloaded);
                                ocspResponse = nextCert.Verify(nextIssuer, validationTime, ocsps);
                                if (ocspResponse != null) RevocationCache.PutOcsp(nextCert, nextIssuer, ocspResponse);
                            }
                        }
                    }
                    catch (RevocationException<OcspResponse>)
                    {
                        throw;
                    }
                    catch (RevocationException<CertificateRevocationList>)
                    {
                        throw;
                    }
                    catch (Exception e)
                    {
                        OperationScope.Cancellation.ThrowIfCancellationRequested();
                        ocspResponse = null;
                        trace.TraceEvent(TraceEventType.Warning, 0, "OCSP validation of {0} failed, falling back to CRL: {1}", nextCert.Subject, e.Message);
                    }

                    if (ocspResponse == null)
                    {
                        CertificateRevocationList crl = nextCert.Verify(nextIssuer, validationTime, crls);
                        if (crl == null && RevocationCache.TryGetCrl(nextCert, nextIssuer, out CertificateRevocationList cachedCrl))
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
                catch (RevocationException<OcspResponse> revoked)
                {
                    RevocationCache.PutOcsp(nextCert, nextIssuer, revoked.RevocationInfo);
                    AddErrorStatus(chain.ChainStatus, chain.ChainElements[i].ChainElementStatus, X509ChainStatusFlags.Revoked, "The certificate has been revoked");
                }
                catch (RevocationException<CertificateRevocationList> revoked)
                {
                    RevocationCache.PutCrl(nextCert, nextIssuer, revoked.RevocationInfo);
                    AddErrorStatus(chain.ChainStatus, chain.ChainElements[i].ChainElementStatus, X509ChainStatusFlags.Revoked, "The certificate has been revoked");
                }
                catch
                {
                    OperationScope.Cancellation.ThrowIfCancellationRequested();
                    AddErrorStatus(chain.ChainStatus, chain.ChainElements[i].ChainElementStatus, X509ChainStatusFlags.RevocationStatusUnknown, "Invalid OCSP/CRL found");
                }
            }
            return chain;
        }

        private static bool VerifyAvailableCrl(X509Certificate2 cert, X509Certificate2 issuer, DateTime time, IList<CertificateRevocationList> crls)
        {
            try
            {
                if (cert.Verify(issuer, time, crls) != null) return true;
                if (!RevocationCache.TryGetCrl(cert, issuer, out var cached)) return false;
                crls.Add(cached);
                return cert.Verify(issuer, time, crls) != null;
            }
            catch (RevocationException<CertificateRevocationList>) { throw; }
            catch (Exception error)
            {
                OperationScope.Cancellation.ThrowIfCancellationRequested();
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
            return certificate.Extensions["1.3.6.1.5.5.7.48.1.5"] != null;
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
        public static OcspResponse Verify(this X509Certificate2 certificate, X509Certificate2 issuer, DateTime validationTime, IList<OcspResponse> ocspResponses)
        {
            var selected = ocspResponses.Select(response => new { Response = response, Status = response.Match(certificate, issuer, validationTime, ClockSkewness) })
                .Where(item => item.Status != null).OrderByDescending(item => item.Status.ThisUpdate).FirstOrDefault();
            if (selected == null) return null;
            selected.Response.Verify(issuer);
            if (selected.Status.Status == 2) throw new RevocationUnknownException("OCSP responder does not know this certificate");
            if (selected.Status.RevocationTime <= validationTime + ClockSkewness)
                throw new RevocationException<OcspResponse>(selected.Response, "The certificate was revoked on " + selected.Status.RevocationTime.Value.ToString("o"));
            return selected.Response;
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
        public static CertificateRevocationList Verify(this X509Certificate2 certificate, X509Certificate2 issuer, DateTime validationTime, IList<CertificateRevocationList> certLists)
        {
            var crl = certLists.Where(value => value.Covers(certificate, issuer) && value.ThisUpdate <= DateTime.UtcNow + ClockSkewness &&
                (value.ThisUpdate >= validationTime - ClockSkewness || value.NextUpdate >= validationTime - ClockSkewness))
                .OrderByDescending(value => value.ThisUpdate).FirstOrDefault();
            if (crl == null) return null;
            crl.Verify(issuer);
            DateTime? revoked = crl.RevocationTime(certificate);
            if (revoked <= validationTime + ClockSkewness)
                throw new RevocationException<CertificateRevocationList>(crl, "The certificate was revoked on " + revoked.Value.ToString("o"));
            return crl;
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
        public static OcspResponse GetOcspResponse(this X509Certificate2 cert, X509Certificate2 issuer)
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
        public static Task<OcspResponse> GetOcspResponseAsync(this X509Certificate2 cert, X509Certificate2 issuer)
            => GetOcspResponseAsync(cert, issuer, OperationScope.Cancellation);

        /// <summary>Downloads OCSP evidence, cancelling only this waiter when a fetch is shared.</summary>
        public static async Task<OcspResponse> GetOcspResponseAsync(this X509Certificate2 cert, X509Certificate2 issuer, CancellationToken cancellationToken)
        {
            using (var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, OperationScope.Cancellation))
            {
                cancellationToken = linked.Token;
                cancellationToken.ThrowIfCancellationRequested();
                Exception lastException = null;
                byte[] ocspReqBytes = null;
                foreach (Uri uri in cert.GetOCSPUris())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        if (ocspReqBytes == null) ocspReqBytes = cert.GetOcspReqBody(issuer);

                        byte[] request = ocspReqBytes;
                        return await ocspDownloads.RunAsync(uri.AbsoluteUri + "|" + issuer.Thumbprint + "|" + cert.SerialNumber,
                            token => DownloadOcspAsync(uri, request, token), cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception e)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        lastException = e;
                        trace.TraceEvent(TraceEventType.Warning, 0, "Failed to manually obtain ocsp: {0}", e);
                    }
                }
                if (lastException != null) throw lastException;
                return null;
            }
        }

        private static async Task<OcspResponse> DownloadOcspAsync(Uri uri, byte[] request, CancellationToken cancellationToken)
        {
            long started = Stopwatch.GetTimestamp(); string outcome = "ok";
            try
            {
                using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                using (var content = new ByteArrayContent(request))
                {
                    cts.CancelAfter(OcspTimeout);
                    content.Headers.ContentType = new MediaTypeHeaderValue("application/ocsp-request");
                    using (var response = await http.PostAsync(uri, content, cts.Token).ConfigureAwait(false))
                    {
                        VerifyOCSPRsp(response);
                        byte[] body = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                        EHealthMetrics.RevocationDownloadBytes.Add(body.Length, new TagList { { "type", "ocsp" } });
                        return ParseOCSPResponse(body);
                    }
                }
            }
            catch (Exception error) { outcome = EHealthMetrics.Outcome(error); throw; }
            finally { EHealthMetrics.Record(EHealthMetrics.RevocationDownloads, EHealthMetrics.RevocationDownloadDuration, started, new TagList { { "type", "ocsp" }, { "outcome", outcome } }); }
        }

        private static byte[] GetOcspReqBody(this X509Certificate2 cert, X509Certificate2 issuer)
        {
            var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
            using (writer.PushSequence()) using (writer.PushSequence()) using (writer.PushSequence()) using (writer.PushSequence()) using (writer.PushSequence())
            {
                CryptoEncoding.WriteAlgorithm(writer, CryptoEncoding.Sha1);
                writer.WriteOctetString(CryptoEncoding.Hash(CryptoEncoding.Sha1, issuer.SubjectName.RawData));
                writer.WriteOctetString(CryptoEncoding.Hash(CryptoEncoding.Sha1, issuer.PublicKey.EncodedKeyValue.RawData));
                writer.WriteIntegerUnsigned(CryptoEncoding.Serial(cert));
            }
            return writer.Encode();
        }
        private static OcspResponse ParseOCSPResponse(byte[] bytes) => OcspResponse.Parse(bytes);
        private static IEnumerable<Uri> GetOCSPUris(this X509Certificate2 cert)
        {
            var extension = cert.Extensions["1.3.6.1.5.5.7.1.1"];
            if (extension == null) yield break;
            var descriptions = CryptoEncoding.Sequence(extension.RawData);
            while (descriptions.HasData)
            {
                var description = descriptions.ReadSequence(); var method = description.ReadObjectIdentifier();
                if (method == "1.3.6.1.5.5.7.48.1" && description.PeekTag().HasSameClassAndValue(CryptoEncoding.Context(6, false)))
                {
                    var address = description.ReadCharacterString(System.Formats.Asn1.UniversalTagNumber.IA5String, CryptoEncoding.Context(6, false));
                    if (Uri.TryCreate(address, UriKind.Absolute, out var uri) && (uri.Scheme == "https" || uri.Scheme == "http")) yield return uri;
                }
            }
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
        public static CertificateRevocationList GetCertificateList(this X509Certificate2 cert)
        {
            return cert.GetCertificateListAsync().ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Download the crl from the server
        /// </summary>
        /// <param name="cert">the certificat to tge the server info from</param>
        /// <returns>The clr (parsed) or <c>null</c> when none found</returns>
        /// <exception cref="RevocationUnknownException">When the revocation info can be retreived</exception>
        public static Task<CertificateRevocationList> GetCertificateListAsync(this X509Certificate2 cert)
            => GetCertificateListAsync(cert, OperationScope.Cancellation);

        /// <summary>Downloads a CRL, cancelling only this waiter when a fetch is shared.</summary>
        public static async Task<CertificateRevocationList> GetCertificateListAsync(this X509Certificate2 cert, CancellationToken cancellationToken)
        {
            using (var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, OperationScope.Cancellation))
            {
                cancellationToken = linked.Token;
                cancellationToken.ThrowIfCancellationRequested();
                Exception lastException = null;
                foreach (Uri uri in cert.GetCrlWebUris())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        return await crlDownloads.RunAsync(uri.AbsoluteUri, token => DownloadCrlAsync(uri, token), cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception e)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        lastException = e;
                        trace.TraceEvent(TraceEventType.Warning, 0, "Failed to manually obtain crl: {0}", e);
                    }
                }
                if (lastException != null) throw lastException;
                return null;
            }
        }

        private static async Task<CertificateRevocationList> DownloadCrlAsync(Uri uri, CancellationToken cancellationToken)
        {
            long started = Stopwatch.GetTimestamp(); string outcome = "ok";
            try
            {
                using (var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    cts.CancelAfter(CrlTimeout);
                    using (var response = await http.GetAsync(uri, cts.Token).ConfigureAwait(false))
                    {
                        VerifyCrlRsp(response);
                        var body = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                        EHealthMetrics.RevocationDownloadBytes.Add(body.Length, new TagList { { "type", "crl" } });
                        return CertificateRevocationList.Parse(body);
                    }
                }
            }
            catch (Exception error) { outcome = EHealthMetrics.Outcome(error); throw; }
            finally { EHealthMetrics.Record(EHealthMetrics.RevocationDownloads, EHealthMetrics.RevocationDownloadDuration, started, new TagList { { "type", "crl" }, { "outcome", outcome } }); }
        }

        private static void VerifyCrlRsp(HttpResponseMessage webRsp)
        {
            if (webRsp.StatusCode != HttpStatusCode.OK)
            {
                trace.TraceEvent(TraceEventType.Error, 0, "Invalid http status for crl reply: {0}", webRsp.ReasonPhrase);
                throw new RevocationUnknownException("Response with invalid status the crl reply: " + webRsp.ReasonPhrase);
            }
        }

        private static IEnumerable<Uri> GetCrlWebUris(this X509Certificate2 cert) => CertificateRevocationList.DownloadUris(cert);

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

