// SPDX-FileCopyrightText: 2021 Duo Security
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

        // Certificates exported from the web site 2022-03-09
        protected const string DUO_API_CERT_SERVER = "MIIH0zCCBrugAwIBAgIQATqA/dmRlE1FQRYim5kzkDANBgkqhkiG9w0BAQsFADBwMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMS8wLQYDVQQDEyZEaWdpQ2VydCBTSEEyIEhpZ2ggQXNzdXJhbmNlIFNlcnZlciBDQTAeFw0yMjAzMDIwMDAwMDBaFw0yMzA0MDIyMzU5NTlaMGsxCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhNaWNoaWdhbjESMBAGA1UEBxMJQW5uIEFyYm9yMRkwFwYDVQQKExBEdW8gU2VjdXJpdHkgTExDMRowGAYDVQQDDBEqLmR1b3NlY3VyaXR5LmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKGWtT2do8lVflEai4UAdOc019bQyQ4XjUHKVmbHwUxShpmwetLusu4+A0MPLbwZko9kwYCXK8TxrVzABIAWw5CqirJWr80+KucmtFVUgxqFav7vUIJnY/BaWDGkiLSMCLz8HToxi8Fp86rQjTM08AEjPLYMlvU41HlWTvuxQT6HdR0uQovhJ1Qrn4IMlrCoLoPkisPWtVaVX/cMJEqWtT/M89mCiczqNxzE7YMDVwRZowDdmC/T6ujo09mCUkl/uojBlENEiFHKIfjz7SDItDGsFmM0ucRv5Mxfvz80mNkoyRIDK8vL2hq7AzdO3qgjL+ZGT3g9H6YCUqKy16SI/PU6nhS48edpuMB6C1m26dldBszK7foeBqtx59WpztYJAlbClaVDuM88DMYANIiduGn3GY7aTlIXn+lHJh1RoLalCh6aOZs3v/2+ggLeGj75vtqhr91aFJozbgu4OtQZkfSepYt/5dZAHCimuJnNH+euDvWtrj10DQ8ToIXQd0vxQ7QbDY8dMjsGi9vYzL8QPOmF/iTBt5V663K83Kjy1hm/QrKOKbAyak8rsyBYndwEXmCpVEHRI90ECCyVBGzX5pjVEtBP0ZZWem9x6K4kwx1xCQl0mOVdmwro9lBLw3HNAj4/S0R77ZVhgHXgkL2vFozkGSSyYrw6sBfr9685FMSDAgMBAAGjggNsMIIDaDAfBgNVHSMEGDAWgBRRaP+QrwIHdTzM2WVkYqISuFlyOzAdBgNVHQ4EFgQUHANgvmzsw2ofi4cQ9W7b1BJYs20wLQYDVR0RBCYwJIIRKi5kdW9zZWN1cml0eS5jb22CD2R1b3NlY3VyaXR5LmNvbTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHUGA1UdHwRuMGwwNKAyoDCGLmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWhhLXNlcnZlci1nNi5jcmwwNKAyoDCGLmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWhhLXNlcnZlci1nNi5jcmwwPgYDVR0gBDcwNTAzBgZngQwBAgIwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMIGDBggrBgEFBQcBAQR3MHUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBNBggrBgEFBQcwAoZBaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkhpZ2hBc3N1cmFuY2VTZXJ2ZXJDQS5jcnQwCQYDVR0TBAIwADCCAX4GCisGAQQB1nkCBAIEggFuBIIBagFoAHcA6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4AAAF/TKU0oAAABAMASDBGAiEAhhSnzx392jnLqxjI4OKypVLQ8DD5GLG06IAV7Ajmr8oCIQCWAtF/QHRDtAenfkplcQ4pzNfPGq0WOwHHHygXFg6bxgB1ALNzdwfhhFD4Y4bWBancEQlKeS2xZwwLh9zwAw55NqWaAAABf0ylNQgAAAQDAEYwRAIgBVuyQ38fIBW+GjBE9PbmMvtlyP9HzaF4XigzUNRkrfsCIGJzhTwCpI7UVXYLOXM0jKA3DBIVah06ohtRQSaG/S0wAHYAtz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJkAAAF/TKU02QAABAMARzBFAiEAyHdWYdIzJUzcvaqOsSThLtBuVtFlGpIWHmzg9gZlf1MCIEUr9IZ7zXAs+6sD/j9T4GMgwJxoKvns7aM+qvRjvh3qMA0GCSqGSIb3DQEBCwUAA4IBAQAp5YyMInyd7dik2lkQ09rugqVY+8idT9QKcEF1OzwcsSNg1RiHJg3lpTjRrG7EBvPghaPhAeWIDnpoeqXroixvp/pIBbWxSJX7a4Zzu7HTGHARbxkN5+wmIsXV+zq0FK/uKi74B5slaeXGGIhUnNpFt9E1IBW8425G0FkVb0A5/paEwEZFqhSOWgxclwqGqMdqIY9jYCTkHdV5YU5hw/yBQPy9eNBwV/jRu92+1iEdwYvQHi6O+Lb+xGQwPHeVEIwbdZ3B1ZeQlIlkMhPYF12R0862VQ8SKLFNdr1i8cgt4PraFKwV2PZ0JWFE9DU/9jfk1ZSyXtEn6miu4GXef4sH";

        // Certificates exported from the web sites 2021-09-22
        protected const string DUO_API_CERT_INTER = "MIIEsTCCA5mgAwIBAgIQBOHnpNxc8vNtwCtCuF0VnzANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEvMC0GA1UEAxMmRGlnaUNlcnQgU0hBMiBIaWdoIEFzc3VyYW5jZSBTZXJ2ZXIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC24C/CJAbIbQRf1+8KZAayfSImZRauQkCbztyfn3YHPsMwVYcZuU+UDlqUH1VWtMICKq/QmO4LQNfE0DtyyBSe75CxEamu0si4QzrZCwvV1ZX1QK/IHe1NnF9Xt4ZQaJn1itrSxwUfqJfJ3KSxgoQtxq2lnMcZgqaFD15EWCo3j/018QsIJzJa9buLnqS9UdAn4t07QjOjBSjEuyjMmqwrIw14xnvmXnG3Sj4I+4G3FhahnSMSTeXXkgisdaScus0Xsh5ENWV/UyU50RwKmmMbGZJ0aAo3wsJSSMs5WqK24V3B3aAguCGikyZvFEohQcftbZvySC/zA/WiaJJTL17jAgMBAAGjggFJMIIBRTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wSwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNybDA9BgNVHSAENjA0MDIGBFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAdBgNVHQ4EFgQUUWj/kK8CB3U8zNllZGKiErhZcjswHwYDVR0jBBgwFoAUsT7DaQP4v0cB1JgmGggC72NkK8MwDQYJKoZIhvcNAQELBQADggEBABiKlYkD5m3fXPwdaOpKj4PWUS+Na0QWnqxj9dJubISZi6qBcYRb7TROsLd5kinMLYBq8I4g4Xmk/gNHE+r1hspZcX30BJZr01lYPf7TMSVcGDiEo+afgv2MW5gxTs14nhr9hctJqvIni5ly/D6q1UEL2tU2ob8cbkdJf17ZSHwD2f2LSaCYJkJA69aSEaRkCldUxPUd1gJea6zuxICaEnL6VpPX/78whQYwvwt/Tv9XBZ0k7YXDK/umdaisLRbvfXknsuvCnQsH6qqF0wGjIChBWUMo0oHjqvbsezt3tkBigAVBRQHvFwY+3sAzm2fTYS5yh+Rp/BIAV0AecPUeybQ=";
        protected const string DUO_API_CERT_ROOT = "MIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTMxMTExMDAwMDAwMFowbDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2UgRVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm+9S75S0tMqbf5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTWPNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEMxChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFBIk5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQNAQTXKFx01p8VdteZOE3hzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsgEsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaAFLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3NecnzyIZgYIVyHbIUf4KmeqvxgydkAQV8GK83rZEWWONfqe/EW1ntlMMUu4kehDLI6zeM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFpmyPInngiK3BD41VHMWEZ71jFhS9OMPagMRYjyOfiZRYzy78aG6A9+MpeizGLYAiJLQwGXFK3xPkKmNEVX58Svnw2Yzi9RKR/5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2/S6cCZdkGCevEsXCS+0yx5DaMkHJ8HSXPfqIbloEpw8nL+e/IBcm2PN7EeqJSdnoDfzAIJ9VNep+OkuE6N36B9K";

        protected const string MICROSOFT_COM_CERT_SERVER = "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";
        protected const string MICROSOFT_COM_CERT_INTER = "MIIFWjCCBEKgAwIBAgIQDxSWXyAgaZlP1ceseIlB4jANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJJRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYDVQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTIwMDcyMTIzMDAwMFoXDTI0MTAwODA3MDAwMFowTzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEgMB4GA1UEAxMXTWljcm9zb2Z0IFJTQSBUTFMgQ0EgMDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCqYnfPmmOyBoTzkDb0mfMUUavqlQo7Rgb9EUEf/lsGWMk4bgj8T0RIzTqk970eouKVuL5RIMW/snBjXXgMQ8ApzWRJCZbar879BV8rKpHoAW4uGJssnNABf2n17j9TiFy6BWy+IhVnFILyLNK+W2M3zK9gheiWa2uACKhuvgCca5Vw/OQYErEdG7LBEzFnMzTmJcliW1iCdXby/vI/OxbfqkKD4zJtm45DJvC9Dh+hpzqvLMiK5uo/+aXSJY+SqhoIEpz+rErHw+uAlKuHFtEjSeeku8eR3+Z5ND9BSqc6JtLqb0bjOHPm5dSRrgt4nnil75bjc9j3lWXpBb9PXP9Sp/nPCK+nTQmZwHGjUnqlO9ebAVQD47ZisFonnDAmjrZNVqEXF3p7laEHrFMxttYuD81BdOzxAbL9Rb/8MeFGQjE2Qx65qgVfhH+RsYuuD9dUw/3wZAhq05yO6nk07AM9c+AbNtRoEcdZcLCHfMDcbkXKNs5DJncCqXAN6LhXVERCw/usG2MmCMLSIx9/kwt8bwhUmitOXc6fpT7SmFvRAtvxg84wUkg4Y/Gx++0j0z6StSeN0EJz150jaHG6WV4HUqaWTb98Tm90IgXAU4AW2GBOlzFPiU5IY9jt+eXC2Q6yC/ZpTL1LAcnL3Qa/OgLrHN0wiw1KFGD51WRPQ0Sh7QIDAQABo4IBJTCCASEwHQYDVR0OBBYEFLV2DDARzseSQk1Mx1wsyKkM6AtkMB8GA1UdIwQYMBaAFOWdWTCCR1jMrPoIVDaGezq1BE3wMA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTA6BgNVHR8EMzAxMC+gLaArhilodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vT21uaXJvb3QyMDI1LmNybDAqBgNVHSAEIzAhMAgGBmeBDAECATAIBgZngQwBAgIwCwYJKwYBBAGCNyoBMA0GCSqGSIb3DQEBCwUAA4IBAQCfK76SZ1vae4qt6P+dTQUO7bYNFUHR5hXcA2D59CJWnEj5na7aKzyowKvQupW4yMH9fGNxtsh6iJswRqOOfZYC4/giBO/gNsBvwr8uDW7t1nYoDYGHPpvnpxCM2mYfQFHq576/TmeYu1RZY29C4w8xYBlkAA8mDJfRhMCmehk7cN5FJtyWRj2cZj/hOoI45TYDBChXpOlLZKIYiG1giY16vhCRi6zmPzEwv+tk156N6cGSVm44jTQ/rs1sa0JSYjzUaYngoFdZC4OfxnIkQvUIA4TOFmPzNPEFdjcZsgbeEz4TcGHTBPK4R28F44qIMCtHRV55VMX53ev6P3hRddJb";
        protected const string MICROSOFT_COM_CERT_ROOT = "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYDVQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoXDTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9yZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVyVHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKrmD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjrIZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeKmpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSuXmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZydc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/yejl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT929hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3WgxjkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhzksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLSR9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp";
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
            Assert.AreEqual(10, CertificatePinnerFactory.ReadCertsFromFile().Length);
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
