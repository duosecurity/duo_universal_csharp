// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

/*
 * This class implements certificate pinning for Duo connections.
 * When an API call is made it uses this class to verify the certificate chain presented by the server.
 * The trust anchors are the CA certificates bundled in ca_certs.pem (or the custom roots supplied to the
 * ClientBuilder); the OS trust store is not required to contain them. A connection is allowed when the
 * server's chain is valid and ends at one of the anchors. When the OS has already validated the chain,
 * it is enough for the SHA-256 hash of the SubjectPublicKeyInfo (SPKI) of some chain certificate to match
 * an anchor's.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DuoUniversal
{
    internal class CertificatePinnerFactory
    {
        // id-kp-serverAuth (RFC 5280 section 4.2.1.12)
        private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

        private readonly X509Certificate2Collection _trustAnchors;
        private readonly HashSet<string> _pinnedSpkiHashes;
        private readonly DateTime? _verificationTime;

        /// <summary>
        /// Prepare a Factory to build a certificate pinner for the specified trust anchors
        /// </summary>
        /// <param name="trustAnchors">The root certificates to pin to</param>
        public CertificatePinnerFactory(X509Certificate2Collection trustAnchors)
            : this(trustAnchors, null)
        {
        }

        /// <summary>
        /// Prepare a Factory to build a certificate pinner for the specified trust anchors
        /// </summary>
        /// <param name="trustAnchors">The root certificates to pin to</param>
        /// <param name="verificationTime">
        /// The time to validate a rebuilt chain at; the current time if null. Only tests should set this,
        /// so that they can use recorded certificates that later expire.
        /// </param>
        internal CertificatePinnerFactory(X509Certificate2Collection trustAnchors, DateTime? verificationTime)
        {
            _trustAnchors = trustAnchors;
            _pinnedSpkiHashes = new HashSet<string>(trustAnchors.Cast<X509Certificate2>().Select(ComputeSpkiHash));
            _verificationTime = verificationTime;
        }

        /// <summary>
        /// Get a certificate pinner that ensures only connections to a specific list of Duo root certificates are allowed
        /// </summary>
        /// <returns>A Duo certificate pinner for use in an HttpClientHandler</returns>
        public static Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> GetDuoCertificatePinner()
        {
            return new CertificatePinnerFactory(GetDuoCertCollection()).PinCertificate;
        }

        /// <summary>
        /// Get a certificate "pinner" that effectively disables SSL certificate validation
        /// </summary>
        /// <returns></returns>
        public static Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> GetCertificateDisabler()
        {
            return (httpRequestMessage, certificate, chain, sslPolicyErrors) => { return true; };
        }

        /// <summary>
        /// Get a certificate validator that performs standard chain validation (trust, expiry, hostname)
        /// but does not enforce certificate pinning.
        /// </summary>
        /// <returns>A certificate validator for use in an HttpClientHandler</returns>
        public static Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> GetCertificateValidatorWithoutPinning()
        {
            return (httpRequestMessage, certificate, chain, sslPolicyErrors) =>
            {
                return sslPolicyErrors == SslPolicyErrors.None;
            };
        }

        /// <summary>
        /// Get a certificate pinner that ensures only connections to the root certificates provided to the constructor are allowed
        /// </summary>
        /// <returns>A certificate pinner for use in an HttpClientHandler</returns>
        public Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> GetPinner()
        {
            return PinCertificate;
        }

        /// <summary>
        /// Allow only connections whose certificate chains to one of the trust anchors, and reject all others.
        /// NB that the certificate and chain have already been checked against the OS trust store, and the status
        /// of that check is available in the chain ChainStatus and overall SslPolicyErrors.
        ///
        /// A connection is allowed in either of two ways:
        ///
        /// 1. Fast path: the OS validated the chain with no errors, and the SPKI hash of some certificate in the
        ///    chain matches an anchor's. Matching on the SPKI rather than the certificate DER is robust against
        ///    cross-signing, since the self-signed and cross-signed forms of a CA share a public key.
        ///
        /// 2. Otherwise, the chain is rebuilt with the anchors as the only trust anchors (see
        ///    <see cref="ChainsToTrustAnchor"/>). This lets the client connect when the OS trust store is missing
        ///    or has a stale copy of Duo's roots, without having to download them.
        ///
        /// A hostname mismatch or a missing certificate is always rejected.
        /// </summary>
        /// <param name="requestMessage">The actual request (unused)</param>
        /// <param name="certificate">The server certificate presented to the connection</param>
        /// <param name="chain">The full certificate chain presented to the connection</param>
        /// <param name="sslPolicyErrors">The current result of the certificate checks</param>
        /// <returns>true if the connection should be allowed, false otherwise</returns>
        internal bool PinCertificate(HttpRequestMessage requestMessage,
                                     X509Certificate2 certificate,
                                     X509Chain chain,
                                     SslPolicyErrors sslPolicyErrors)
        {
            // If there's no server certificate or chain, fail
            if (certificate == null || chain == null)
            {
                return false;
            }

            // The platform checks the hostname separately from the chain, so a name mismatch (or no certificate
            // at all) is fatal whatever the chain looks like. Only chain errors can be resolved by validating
            // against our own anchors.
            if ((sslPolicyErrors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None)
            {
                return false;
            }

            // Fast path: the OS validated the chain and it contains a pinned key.
            if (sslPolicyErrors == SslPolicyErrors.None &&
                chain.ChainStatus.All(status => status.Status == X509ChainStatusFlags.NoError) &&
                ChainContainsPinnedSpki(chain))
            {
                return true;
            }

            // The OS could not validate the chain (e.g. Duo's root is missing from its trust store), or validated
            // it to a root we do not pin: decide using our own anchors.
            return ChainsToTrustAnchor(certificate, chain);
        }

        /// <summary>
        /// Return true if any certificate in the chain has an SPKI hash in the pinned set.
        /// </summary>
        private bool ChainContainsPinnedSpki(X509Chain chain)
        {
            foreach (X509ChainElement element in chain.ChainElements)
            {
                string hash = ComputeSpkiHash(new X509Certificate2(element.Certificate));
                if (_pinnedSpkiHashes.Contains(hash))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Rebuild the server's chain with the anchors as the only trust anchors, and return true if it is valid
        /// and ends at one of them.
        ///
        /// .NET Framework and netstandard2.0 have no way to replace the trust store of an X509Chain, so this uses
        /// the standard pattern for a custom trust anchor: put the anchors in the ExtraStore so the chain can be
        /// completed without the OS store, allow an unknown root, then require that the root the chain actually
        /// ended at is byte-for-byte one of the anchors. The platform still checks every signature, validity
        /// period, basic constraint, name constraint and key usage, the serverAuth extended key usage, and the OS
        /// distrust list (ExplicitDistrust).
        /// </summary>
        private bool ChainsToTrustAnchor(X509Certificate2 certificate, X509Chain presentedChain)
        {
            using (var chain = new X509Chain())
            {
                X509ChainPolicy policy = chain.ChainPolicy;
                policy.ExtraStore.AddRange(_trustAnchors);
                policy.ExtraStore.AddRange(PresentedIntermediates(presentedChain));
                // Tolerate only UntrustedRoot. In particular this does not ignore expiry, usage or constraint
                // errors. It does let Build() return true for a chain that could not be completed (PartialChain),
                // so the status is checked below rather than relying on the return value.
                policy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                policy.ApplicationPolicy.Add(new Oid(ServerAuthOid));
                // Match the HttpClientHandler the Client uses, which does not check revocation.
                policy.RevocationMode = X509RevocationMode.NoCheck;
                policy.VerificationTime = _verificationTime ?? DateTime.Now;
                // netstandard2.0 and net471 cannot disable certificate downloads (AIA). A download can only
                // produce a chain that does not end at an anchor, which is rejected below.

                chain.Build(certificate);

                if (chain.ChainElements.Count == 0 ||
                    !chain.ChainStatus.All(status => IsAcceptableStatus(status.Status)))
                {
                    return false;
                }
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    if (!element.ChainElementStatus.All(status => IsAcceptableStatus(status.Status)))
                    {
                        return false;
                    }
                }

                // UntrustedRoot only says the chain ended at some self-signed certificate. It must be one of ours:
                // matching a pinned key alone is not enough, since a pinned key re-wrapped in a certificate from
                // another root would bypass the real CA certificate's validity and constraints.
                X509Certificate2 root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                return IsTrustAnchor(root);
            }
        }

        /// <summary>
        /// The only chain statuses accepted on a rebuilt chain. UntrustedRoot means the chain ended at a
        /// self-signed certificate that the OS does not trust, which is expected when it is one of our anchors.
        /// PartialChain and every other error are rejected.
        /// </summary>
        private static bool IsAcceptableStatus(X509ChainStatusFlags status)
        {
            return status == X509ChainStatusFlags.NoError ||
                   status == X509ChainStatusFlags.UntrustedRoot;
        }

        /// <summary>
        /// The CA certificates the server presented, for completing the rebuilt chain. Any self-signed certificate
        /// is left out so that only our anchors can end the chain.
        /// </summary>
        private static X509Certificate2Collection PresentedIntermediates(X509Chain presentedChain)
        {
            var candidates = new List<X509Certificate2>();
            // .NET 5+ passes the certificates the server sent in the ExtraStore; .NET Framework only exposes the
            // chain the OS built from them.
            candidates.AddRange(presentedChain.ChainPolicy.ExtraStore.Cast<X509Certificate2>());
            candidates.AddRange(presentedChain.ChainElements.Cast<X509ChainElement>()
                                                            .Skip(1)
                                                            .Select(element => element.Certificate));

            var intermediates = new X509Certificate2Collection();
            foreach (X509Certificate2 cert in candidates)
            {
                if (!cert.SubjectName.RawData.SequenceEqual(cert.IssuerName.RawData))
                {
                    intermediates.Add(cert);
                }
            }
            return intermediates;
        }

        private bool IsTrustAnchor(X509Certificate2 cert)
        {
            return _trustAnchors.Cast<X509Certificate2>().Any(anchor => anchor.RawData.SequenceEqual(cert.RawData));
        }

        /// <summary>
        /// Get the root certificates allowed by Duo, from the embedded ca_certs.pem
        /// </summary>
        /// <returns>A X509Certificate2Collection of the allowed root certificates</returns>
        internal static X509Certificate2Collection GetDuoCertCollection()
        {
            X509Certificate2Collection coll = new X509Certificate2Collection();
            foreach (string oneCert in ReadCertsFromFile())
            {
                byte[] der = DecodePemCertificate(oneCert);
                if (der != null)
                {
                    coll.Add(new X509Certificate2(der));
                }
            }
            return coll;
        }

        /// <summary>
        /// Read the embedded Duo ca_certs.pem certificates file to get an array of certificate strings
        /// </summary>
        /// <returns>The Duo root CA certificates as strings</returns>
        internal static string[] ReadCertsFromFile()
        {
            var certs = "";

            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("DuoUniversal.ca_certs.pem"))
            using (StreamReader reader = new StreamReader(stream))
            {
                certs = reader.ReadToEnd();
            }
            var splitOn = "-----DUO_CERT-----";
            return certs.Split(new string[] { splitOn }, int.MaxValue, StringSplitOptions.None);
        }

        /// <summary>
        /// Extract the DER bytes of a single certificate from a PEM block that may be surrounded by comment lines.
        /// This is parsed explicitly, rather than relying on X509Certificate2 to interpret PEM, so certificate
        /// loading behaves identically across .NET Framework and .NET Core.
        /// </summary>
        private static byte[] DecodePemCertificate(string pem)
        {
            const string begin = "-----BEGIN CERTIFICATE-----";
            const string end = "-----END CERTIFICATE-----";

            int start = pem.IndexOf(begin, StringComparison.Ordinal);
            if (start < 0)
            {
                return null;
            }
            start += begin.Length;

            int stop = pem.IndexOf(end, start, StringComparison.Ordinal);
            if (stop < 0)
            {
                return null;
            }

            string base64 = pem.Substring(start, stop - start)
                               .Replace("\r", "")
                               .Replace("\n", "")
                               .Trim();
            return Convert.FromBase64String(base64);
        }

        /// <summary>
        /// Computes the base64-encoded SHA-256 hash of the certificate's SubjectPublicKeyInfo DER structure.
        /// </summary>
        internal static string ComputeSpkiHash(X509Certificate2 cert)
        {
            byte[] spki = ExtractSpkiDer(cert.RawData);
            using (var sha256 = SHA256.Create())
            {
                return Convert.ToBase64String(sha256.ComputeHash(spki));
            }
        }

        /// <summary>
        /// Extracts the SubjectPublicKeyInfo SEQUENCE bytes from a certificate's raw DER.
        /// Navigates: Certificate SEQUENCE -> TBSCertificate SEQUENCE -> skip version/serial/
        /// signatureAlgorithm/issuer/validity/subject -> read SubjectPublicKeyInfo SEQUENCE.
        /// </summary>
        internal static byte[] ExtractSpkiDer(byte[] certDer)
        {
            int pos = 0;

            // Certificate SEQUENCE
            ReadTag(certDer, ref pos, 0x30);
            ReadLength(certDer, ref pos);

            // TBSCertificate SEQUENCE
            ReadTag(certDer, ref pos, 0x30);
            ReadLength(certDer, ref pos);

            // Optional version [0] EXPLICIT
            if (certDer[pos] == 0xA0)
            {
                SkipField(certDer, ref pos);
            }

            // serialNumber INTEGER
            SkipField(certDer, ref pos);

            // signature AlgorithmIdentifier SEQUENCE
            SkipField(certDer, ref pos);

            // issuer Name SEQUENCE
            SkipField(certDer, ref pos);

            // validity SEQUENCE
            SkipField(certDer, ref pos);

            // subject Name SEQUENCE
            SkipField(certDer, ref pos);

            // SubjectPublicKeyInfo SEQUENCE — capture start and total length (tag + length bytes + content)
            int spkiStart = pos;
            ReadTag(certDer, ref pos, 0x30);
            int spkiContentLen = ReadLength(certDer, ref pos);
            int spkiTotalLen = pos - spkiStart + spkiContentLen;

            byte[] spki = new byte[spkiTotalLen];
            Array.Copy(certDer, spkiStart, spki, 0, spkiTotalLen);
            return spki;
        }

        private static void ReadTag(byte[] data, ref int pos, byte expectedTag)
        {
            if (data[pos] != expectedTag)
            {
                throw new FormatException(
                    $"DER parse error: expected tag 0x{expectedTag:X2} at offset {pos}, got 0x{data[pos]:X2}");
            }
            pos++;
        }

        private static int ReadLength(byte[] data, ref int pos)
        {
            int first = data[pos++];
            if (first < 0x80)
            {
                return first;
            }

            int numBytes = first & 0x7F;
            int length = 0;
            for (int i = 0; i < numBytes; i++)
            {
                length = (length << 8) | data[pos++];
            }
            return length;
        }

        private static void SkipField(byte[] data, ref int pos)
        {
            pos++; // skip tag byte
            int len = ReadLength(data, ref pos);
            pos += len;
        }
    }
}
