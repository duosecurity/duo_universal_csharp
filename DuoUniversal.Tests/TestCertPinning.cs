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
            chain.ChainPolicy.VerificationTime = new DateTime(2025, 01, 01);
            chain.ChainPolicy.ExtraStore.Add(CertFromString(MICROSOFT_COM_CERT_ROOT));
            chain.ChainPolicy.ExtraStore.Add(CertFromString(MICROSOFT_COM_CERT_INTER));
            bool valid = chain.Build(CertFromString(MICROSOFT_COM_CERT_SERVER));

            if (!valid)
            {
                Console.WriteLine("The certificate chain is invalid. Details:");

                foreach (var element in chain.ChainElements)
                {
                    Console.WriteLine($"Certificate: {element.Certificate.Subject}");
                    Console.WriteLine($"  NotBefore: {element.Certificate.NotBefore}");
                    Console.WriteLine($"  NotAfter: {element.Certificate.NotAfter}");

                    foreach (var status in element.ChainElementStatus)
                    {
                        Console.WriteLine($"  Status: {status.Status}");
                        Console.WriteLine($"  Information: {status.StatusInformation}");
                    }
                }
            }

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

        // Certificates exported from the web sites 2025-03-17
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
            Assert.AreEqual(15, CertificatePinnerFactory.ReadCertsFromFile().Length);
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
