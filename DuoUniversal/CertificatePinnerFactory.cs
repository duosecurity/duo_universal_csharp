// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

/*
 * This class implements certificate pinning for Duo connections.
 * When an API call is made it uses this class to verify the certificate chain presented by the server.
 * Pinning is done by comparing the SHA-256 hash of the SubjectPublicKeyInfo (SPKI) DER structure of
 * each certificate in the chain against a hardcoded set of known-good hashes (base64-encoded).
 * If any certificate in the chain matches a pinned hash, the connection is allowed.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DuoUniversal
{
    internal class CertificatePinnerFactory
    {
        private readonly HashSet<string> _pinnedSpkiHashes;

        /// <summary>
        /// Prepare a Factory to build a certificate pinner for the specified SPKI hashes
        /// </summary>
        /// <param name="pinnedSpkiHashes">The SPKI hashes to pin to</param>
        public CertificatePinnerFactory(HashSet<string> pinnedSpkiHashes)
        {
            _pinnedSpkiHashes = pinnedSpkiHashes;
        }

        /// <summary>
        /// Get a certificate pinner that ensures only connections to a specific list of Duo root certificates are allowed
        /// </summary>
        /// <returns>A Duo certificate pinner for use in an HttpClientHandler</returns>
        public static Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> GetDuoCertificatePinner()
        {
            return new CertificatePinnerFactory(GetDuoSpkiHashes()).PinCertificate;
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
        /// Get a certificate pinner that ensures only connections to the root certificates provided to the constructor are allowed
        /// </summary>
        /// <returns>A certificate pinner for use in an HttpClientHandler</returns>
        public Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> GetPinner()
        {
            return PinCertificate;
        }

        /// <summary>
        /// Pin only to specified certificates, and reject connections to any others.
        /// NB that the certificate and chain have already been checked, and the status of that check is available
        /// in the chain ChainStatus and overall SslPolicyErrors.
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

            // If the regular certificate checking process failed, fail
            // we want everything to be valid, but then just restrict the acceptable certificates
            if (sslPolicyErrors != SslPolicyErrors.None)
            {
                return false;
            }

            // Double check everything's valid
            if (chain.ChainStatus.Any(status => status.Status != X509ChainStatusFlags.NoError))
            {
                return false;
            }

            // Check that a certificate in the chain matches a pinned SPKI hash
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
        /// Returns the set of pinned SPKI hashes for the Duo root CAs.
        /// </summary>
        internal static HashSet<string> GetDuoSpkiHashes()
        {
            return new HashSet<string>
            {
                "++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI=",
                "f0KW/FtqTjs108NpYj42SrGvOB2PpxIVM8nWxjPqJGE=",
                "NqvDJlas/GRcYbcWE8S/IceH9cq77kg0jVhZeAPXq8k=",
                "9+ze1cZgR9KO1kZrVDxA4HQ6voHRCSVNz4RdTCx4U8U=",
                "KwccWaCgrnaw6tsrrSO61FgLacNgG2MMLq8GE6+oP5I=",
                "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=",
                "oC+voZLIy4HLE0FVT5wFtxzKKokLDRKY1oNkfJYe+98=",
                "ape1HIIZ6T5d7GS61YBs3rD4NVvkfnVwELcCRW4Bqv0=",
                "rn+WLLnmp9v3uDP7GPqbcaiRdd+UnCMrap73yz3yu/w=",
                "4EoCLOMvTM8sf2BGKHuCijKpCfXnUUR/g/0scfb9gXM=",
                "Vfd95BwDeSQo+NUYxVEEIlvkOlWY2SalKK1lPhzOx78=",
                "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=",
                "B+hU8mp8vTiZJ6oEG/7xts0h3RQ4GK2UfcZVqeWH/og=",
                "uu5PB+MS9L3/ffB/PuTG6A+WjsTtTaF52qqjrcHFXRU=",
                "gI1os/q0iEpflxrOfRBVDXqVoWN3Tz7Dav/7IT++THQ=",
            };
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
