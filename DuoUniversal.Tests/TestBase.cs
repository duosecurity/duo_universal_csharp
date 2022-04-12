// SPDX-FileCopyrightText: 2021 Duo Security
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DuoUniversal.Tests
{

    public class TestBase
    {
        // A consistent set of test values
        // A Client Id, e.g. the Issuer of JWTs going to Duo and the Audience of JWTs sent by Duo
        protected const string CLIENT_ID = "client id client id ";
        // A Client Secret, the shared secret used to sign JWTs
        protected const string CLIENT_SECRET = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // A Duo API Host, the basis of endpoints URIs which are the Audience of JWTs going to Duo and the Issuer of JWTs sent dy Duo
        protected const string API_HOST = "fake.api.host";
        // The Issuer of the only JWT sent by Duo
        protected const string DUO_ISSUER = "https://fake.api.host/oauth/v1/token";
        // An example username
        protected const string USERNAME = "username";

        // Some JWT values to test the conversions
        protected const string ALLOW = "allow";
        protected const string BROWSER = "browser";
        protected const string NAME = "name";
        protected const string GEO_STATE = "state";
        internal static string CreateTokenJwt()
        {
            long sampleIat = ((DateTimeOffset)DateTime.Now).ToUnixTimeSeconds() - 60;
            long sampleExp = sampleIat + 300; // 5 minutes later
            // Make a representative id token
            var payloadData = new
            {
                // Duo claims
                auth_context = new
                {
                    access_device = new
                    {
                        browser = BROWSER,
                        browser_version = "1.2.3.4",
                        flash_version = "4.3.2.1",
                        hostname = "hostname",
                        ip = "100.200.100.200",
                        is_encryption_enabled = true,
                        is_firewall_enabled = false,
                        is_password_set = "unknown",
                        java_version = "4.3.2.1",
                        location = new
                        {
                            city = "city",
                            country = "country",
                            state = GEO_STATE,
                        },
                        os = "Mac OS X",
                        os_version = "10.15.7",
                        security_agents = "unknown"
                    },
                    alias = "",
                    application = new
                    {
                        key = "DIXXXXXXXXXXXXXXXXXX",
                        name = "Web SDK 4",
                    },
                    auth_device = new
                    {
                        ip = "200.100.200.100",
                        location = new
                        {
                            city = "city",
                            country = "country",
                            state = GEO_STATE,
                        },
                        name = "name"
                    },
                    email = "",
                    event_type = "authentication",
                    factor = "duo_push",
                    isotimestamp = "2021-08-30T18:00:00.00000+00:00",
                    ood_software = "Windows 3.1",
                    reason = "user_approved",
                    result = "success",
                    timestamp = 1234,
                    trusted_endpoint_status = "unknown",
                    txid = "123456",
                    user = new
                    {
                        groups = new List<string>(),
                        key = "key",
                        name = NAME
                    }
                },
                auth_result = new
                {
                    result = ALLOW,
                    status = "allow",
                    status_msg = "Login successful"
                },
                auth_time = 1234,
                preferred_username = USERNAME,
                // Standard JWT stuff fields (exp, nbf, and iat will be automatically added)
                aud = CLIENT_ID,
                iss = DUO_ISSUER,
                sub = "subject",
                iat = sampleIat,
                exp = sampleExp
            };
            string payload = JsonSerializer.Serialize(payloadData);

            return JwtUtils.CreateJwtFromPayload(payload, CLIENT_SECRET);
        }
    }

    public class ClientTestBase : TestBase
    {
        // The URI on the client application that will serve the redirect from Duo after 2FA
        protected const string REDIRECT_URI = "https://fake.com/fake";
        protected static Client MakeClient(HttpMessageHandler handler)
        {
            return new ClientBuilder(CLIENT_ID, CLIENT_SECRET, API_HOST, REDIRECT_URI).CustomHandler(handler).Build();
        }
    }

    internal class HttpExcepter : HttpMessageHandler
    {
        public HttpExcepter()
        {
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            throw new HttpRequestException("Test Exception");
        }
    }

    internal class HttpResponder : HttpMessageHandler
    {
        private readonly HttpStatusCode statusCode;
        private readonly HttpContent content;

        public HttpResponder(HttpStatusCode statusCode, HttpContent content)
        {
            this.statusCode = statusCode;
            this.content = content;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage() { StatusCode = statusCode, Content = content });
        }
    }
}
