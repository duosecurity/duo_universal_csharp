// SPDX-FileCopyrightText: 2021 Duo Security
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DuoUniversal
{
    internal class CertificatePinnerFactory
    {
        private readonly X509Certificate2Collection _rootCerts;

        /// <summary>
        /// Prepare a Factory to build a certificate pinner for the specified root certificates
        /// </summary>
        /// <param name="rootCerts">The root certificates to pin to</param>
        public CertificatePinnerFactory(X509Certificate2Collection rootCerts)
        {
            _rootCerts = rootCerts;
        }

        /// <summary>
        /// Get a certificate pinner that ensures only connections to a specific list of Duo root certificates are allowed
        /// </summary>
        /// <returns>A Duo certificate pinner for use in an HttpClientHandler</returns>
        public static Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> GetDuoCertificatePinner()
        {
            return new CertificatePinnerFactory(GetDuoCertCollection()).GetPinner();
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
        /// Pin only to specified root certificates, and reject connections to any other roots.
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
            // we want everything to be valid, but then just restrict the acceptable root certificates
            if (sslPolicyErrors != SslPolicyErrors.None)
            {
                return false;
            }

            // Double check everything's valid and grab the root certificate (and double check it's valid)
            if (!chain.ChainStatus.All(status => status.Status == X509ChainStatusFlags.NoError))
            {
                return false;
            }
            var chainLength = chain.ChainElements.Count;
            var rootCert = chain.ChainElements[chainLength - 1].Certificate;
            if (!rootCert.Verify())
            {
                return false;
            }

            // Check that the root certificate is in the allowed list
            var allowedCerts = _rootCerts;
            if (!allowedCerts.Contains(rootCert))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Get the root certificates allowed by Duo in a usable form
        /// </summary>
        /// <returns>A X509CertificateCollection of the allowed root certificates</returns>
        internal static X509Certificate2Collection GetDuoCertCollection()
        {
            var certs = ReadCertsFromFile();

            X509Certificate2Collection coll = new X509Certificate2Collection();
            foreach (string oneCert in certs)
            {
                if (!string.IsNullOrWhiteSpace(oneCert))
                {
                    var bytes = Encoding.UTF8.GetBytes(oneCert);
                    coll.Import(bytes);
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
    }
}
