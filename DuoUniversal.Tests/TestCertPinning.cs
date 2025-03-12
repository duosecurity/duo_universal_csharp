// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;

namespace DuoUniversal.Tests
{

    public class CertPinningTestBase
    {
        // Helper methods and some hard-coded certificates
        protected static X509Certificate2 DuoApiServerCert()
        {
            // The leaf certificate for api-*.duosecurity.com
            return CertFromString(DUO_API_CERT_SERVER);
        }

        protected static X509Chain DuoApiChain()
        {
            // The certificate chain for api-*.duosecurity.com
            var chain = new X509Chain();
            chain.ChainPolicy.VerificationTime = new DateTime(2023, 01, 01);
            chain.ChainPolicy.ExtraStore.Add(CertFromString(DUO_API_CERT_ROOT));
            chain.ChainPolicy.ExtraStore.Add(CertFromString(DUO_API_CERT_INTER));
            bool valid = chain.Build(DuoApiServerCert());
            Assert.True(valid);
            return chain;
        }

        protected static X509Chain MicrosoftComChain()
        {
            // A valid chain, but for www.microsoft.com, not Duo
            var chain = new X509Chain();
            chain.ChainPolicy.VerificationTime = new DateTime(2023, 01, 01);
            chain.ChainPolicy.ExtraStore.Add(CertFromString(MICROSOFT_COM_CERT_ROOT));
            chain.ChainPolicy.ExtraStore.Add(CertFromString(MICROSOFT_COM_CERT_INTER));
            bool valid = chain.Build(CertFromString(MICROSOFT_COM_CERT_SERVER));
            Assert.True(valid);
            return chain;
        }

        protected static X509Certificate2 CertFromString(string certString)
        {
            return new X509Certificate2(Convert.FromBase64String(certString));
        }

        // Certificates exported from the web site 2025-03-12
        protected const string DUO_API_CERT_SERVER = "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";

        // Certificates exported from the web sites 2025-03-12
        protected const string DUO_API_CERT_INTER = "MIIEXjCCA0agAwIBAgITB3MSSkvL1E7HtTvq8ZSELToPoTANBgkqhkiG9w0BAQsFADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSAxMB4XDTIyMDgyMzIyMjUzMFoXDTMwMDgyMzIyMjUzMFowPDELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEcMBoGA1UEAxMTQW1hem9uIFJTQSAyMDQ4IE0wMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtDGMZaqHneKei1by6+pUPPLljTB143Si6VpEWPc6mSkFhZb/6qrkZyoHlQLbDYnI2D7hD0sdzEqfnuAjIsuXQLG3A8TvX6V3oFNBFVe8NlLJHvBseKY88saLwufxkZVwk74g4nWlNMXzla9Y5F3wwRHwMVH443xGz6UtGSZSqQ94eFx5X7Tlqt8whi8qCaKdZ5rNak+r9nUThOeClqFd4oXych//Rc7Y0eX1KNWHYSI1Nk31mYgiK3JvH063g+K9tHA63ZeTgKgndlh+WI+zv7i44HepRZjA1FYwYZ9Vv/9UkC5Yz8/yU65fgjaE+wVHM4e/YyC2osrPWE7gJ+dXMCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUwDFSzVpQw4J8dHHOy+mc+XrrguIwHwYDVR0jBBgwFoAUhBjMhTTsvAyUlC4IWZzHshBOCggwewYIKwYBBQUHAQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8vb2NzcC5yb290Y2ExLmFtYXpvbnRydXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDovL2NydC5yb290Y2ExLmFtYXpvbnRydXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jvb3RjYTEuY3JsMBMGA1UdIAQMMAowCAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IBAQAtTi6Fs0Azfi+iwm7jrz+CSxHH+uHl7Law3MQSXVtR8RV53PtR6r/6gNpqlzdoZq4FKbADi1v9Bun8RY8D51uedRfjsbeodizeBB8nXmeyD33Ep7VATj4ozcd31YFVfgRhvTSxNrrTlNpWkUk0m3BMPv8sg381HhA6uEYokE5q9uws/3YkKqRiEz3TsaWmJqIRZhMbgAfp7O7FUwFIb7UIspogZSKxPIWJpxiPo3TcBambbVtQOcNRWz5qCQdDslI2yayq0n2TXoHyNCLEH8rpsJRVILFsg0jc7BaFrMnF462+ajSehgj12IidNeRN4zl+EoNaWdpnWndvSpAEkq2P";
        protected const string DUO_API_CERT_ROOT = "MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsFADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTELMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXjca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qwIFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQmjgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUAA4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDIU5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUsN+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vvo/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpyrqXRfboQnoZsG4q5WTP468SQvvG5";

        // Certificates exported from the web sites 2025-03-12
        protected const string MICROSOFT_COM_CERT_SERVER = "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";
        protected const string MICROSOFT_COM_CERT_INTER = "MIIFrDCCBJSgAwIBAgIQCfluwpVVXyR0nq8eXc7UnTANBgkqhkiG9w0BAQwFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMjAeFw0yMzA2MDgwMDAwMDBaFw0yNjA4MjUyMzU5NTlaMF0xCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLjAsBgNVBAMTJU1pY3Jvc29mdCBBenVyZSBSU0EgVExTIElzc3VpbmcgQ0EgMDQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDBeUy13eRZ/QC5bN7/IOGxodny7Xm2BFc88d3cca3yHyyVx1Y60+afY6DAo/2Ls1uzAfbDfMzAVWJazPH4tckaItDv//htEbbNJnAGvZPB4VqNviwDEmlAWT/MTAmzXfTgWXuUNgRlzZbjoFaPm+t6iJ6HdvDpWQAJbsBUZCgat257tM28JnAHUTWdiDBn+2z6EGh2DA6BCx04zHDKVSegLY8+5P80Lqze0d6i3T2JJ7rfxCmxUXfCGOv9iQIUZfhv4vCb8hsm/JdNUMiomJhSPa0bi3rda/swuJHCH//dwz2AGzZRRGdj7Kna4t6ToxK17lAF3Q6Qp368C9cE6JLMj+3UbY3umWCPRA5/Dms4/wl3GvDEw7HpyKsvRNPpjDZyiFzZGC2HZmGMsrZMT3hxmyQwmz1O3eGYdO5EIq1SW/vT1yShZTSusqmICQo5gWWRZTwCENekSbVX9qRr77o0pjKtuBMZTGQTixwpT/rgUl7Mr4M2nqK55Kovy/kUN1znfPdW/Fj9iCuvPKwKFdyt2RVgxJDvgIF/bNoRkRxhwVB6qRgs4EiTrNbRoZAHEFF5wRBf9gWn9HeoI66VtdMZvJRH+0/FDWB4/zwxS16nnADJaVPXh6JHJFYs9p0wZmvct3GNdWrOLRAG2yzbfFZS8fJcX1PYxXXo4By16yGWhQIDAQABo4IBYjCCAV4wEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUO3DRU+l2JZ1gqMpmD8abrm9UFmowHwYDVR0jBBgwFoAUTiJUIBiV5uNu5g/6+rkS7QYXjzkwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjB2BggrBgEFBQcBAQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBABggrBgEFBQcwAoY0aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNydDBCBgNVHR8EOzA5MDegNaAzhjFodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxSb290RzIuY3JsMB0GA1UdIAQWMBQwCAYGZ4EMAQIBMAgGBmeBDAECAjANBgkqhkiG9w0BAQwFAAOCAQEAo9sJvBNLQSJ1e7VaG3cSZHBz6zjS70A1gVO1pqsmX34BWDPz1TAlOyJiLlA+eUF4B2OWHd3F//dJJ/3TaCFunjBhZudv3busl7flz42K/BG/eOdlg0kiUf07PCYY5/FKYTIch51j1moFlBqbglwkdNIVae2tOu0OdX2JiA+bprYcGxa7eayLetvPiA77ynTcUNMKOqYB41FZHOXe5IXDI5t2RsDM9dMEZv4+cOb9G9qXcgDar1AzPHEt/39335zCHofQ0QuItCDCDzahWZci9Nn9hb/SvAtPWHZLkLBG6I0iwGxvMwcTTc9Jnb4FlysrmQlwKsS2MphOoI23Qq3cSA==";
        protected const string MICROSOFT_COM_CERT_ROOT = "MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQq2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5WztCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQvIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NGFdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ918rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTepLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTflMrY=";
    }

    [TestFixture]
    public class TestCertPinning : CertPinningTestBase
    {
        private Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> duoPinner;

        [SetUp]
        public void Setup()
        {
            duoPinner = CertificatePinnerFactory.GetDuoCertificatePinner();
        }

        [Test]
        public void TestReadCertFile()
        {
            Assert.AreEqual(1, CertificatePinnerFactory.ReadCertsFromFile().Length);
        }

        [Test]
        public void TestSuccess()
        {
            Assert.True(duoPinner(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.None));
        }

        [Test]
        public void TestNullCertificate()
        {
            Assert.False(duoPinner(null, null, DuoApiChain(), SslPolicyErrors.None));
        }

        [Test]
        public void TestNullChain()
        {
            Assert.False(duoPinner(null, DuoApiServerCert(), null, SslPolicyErrors.None));
        }

        [Test]
        public void TestFatalSslError()
        {
            Assert.False(duoPinner(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.RemoteCertificateNameMismatch));
        }

        [Test]
        public void TestUnmatchedRoot()
        {
            Assert.False(duoPinner(null, DuoApiServerCert(), MicrosoftComChain(), SslPolicyErrors.None));
        }

        [Test]
        public void TestAlternateCertsSuccess()
        {
            var certCollection = new X509Certificate2Collection
            {
                CertFromString(MICROSOFT_COM_CERT_ROOT)
            };

            var pinner = new CertificatePinnerFactory(certCollection).GetPinner();

            Assert.True(pinner(null, CertFromString(MICROSOFT_COM_CERT_SERVER), MicrosoftComChain(), SslPolicyErrors.None));
        }
    }

    [TestFixture]
    public class TestCertDisabling : CertPinningTestBase
    {
        private Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> pinner;

        [SetUp]
        public void Setup()
        {
            pinner = CertificatePinnerFactory.GetCertificateDisabler();
        }

        [Test]
        public void TestSuccess()
        {
            Assert.True(pinner(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.None));
        }

        [Test]
        public void TestNullCertificate()
        {
            Assert.True(pinner(null, null, DuoApiChain(), SslPolicyErrors.None));
        }

        [Test]
        public void TestNullChain()
        {
            Assert.True(pinner(null, DuoApiServerCert(), null, SslPolicyErrors.None));
        }

        [Test]
        public void TestFatalSslError()
        {
            Assert.True(pinner(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.RemoteCertificateNameMismatch));
        }

        [Test]
        public void TestUnmatchedRoot()
        {
            Assert.True(pinner(null, DuoApiServerCert(), MicrosoftComChain(), SslPolicyErrors.None));
        }
    }
}
