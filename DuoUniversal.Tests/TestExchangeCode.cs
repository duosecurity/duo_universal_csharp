// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestExchangeCode : ClientTestBase
    {
        private const string CODE = "code";

        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public async Task TestSuccess()
        {
            string goodResponse = GoodApiResponse();
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(goodResponse)));
            IdToken idToken = await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME);
            Assert.AreEqual(idToken.Username, USERNAME);
        }

        [Test]
        public async Task TestSamlResponseSuccess()
        {
            string goodResponse = GoodApiResponseWithSamlResponse();
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(goodResponse)));
            string samlResponse = await client.ExchangeAuthorizationCodeForSamlResponse(CODE, USERNAME);
            Assert.NotNull(samlResponse);
        }

        [Test]
        [TestCase(HttpStatusCode.MovedPermanently)] // 301
        [TestCase(HttpStatusCode.BadRequest)] // 400
        [TestCase(HttpStatusCode.NotFound)] // 404
        [TestCase(HttpStatusCode.InternalServerError)] // 500
        public void TestBadHttpStatus(HttpStatusCode statusCode)
        {
            var client = MakeClient(new HttpResponder(statusCode, new StringContent("irrelevant")));
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME));
        }

        [Test]
        public void TestHttpException()
        {
            var client = MakeClient(new HttpExcepter());
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME));
        }

        [Test]
        [TestCase("Not username")]
        [TestCase("username@domain.org")]
        [TestCase("  username  ")]
        [TestCase("!@#user$%^name*&(")]
        public void TestUsernameMismatch(string username)
        {
            // Will have the USERNAME specified in the parent class
            string goodResponse = GoodApiResponse();
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(goodResponse)));
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeFor2faResult(CODE, username));
        }

        [Test]
        [TestCase("not username")]
        public void TestUsernameMismatchSamlResponseFailure(string username)
        {
            string goodResponse = GoodApiResponseWithSamlResponse();
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(goodResponse)));
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeForSamlResponse(CODE, username));
        }

        private static string GoodApiResponse()
        {
            var responseValues = new Dictionary<string, string>
            {
                {"access_token", "access token"},
                {"expires_in", "1"},
                {"id_token", CreateTokenJwt()},
                {"token_type", "Bearer"}
            };
            return JsonSerializer.Serialize(responseValues);
        }

        private static string GoodApiResponseWithSamlResponse()
        {
            var responseValues = new Dictionary<string, string>
            {
                {"access_token", "access token"},
                {"expires_in", "1"},
                {"id_token", CreateTokenJwt()},
                {"token_type", "Bearer"},
                {"saml_response", "saml_response"}
            };
            return JsonSerializer.Serialize(responseValues);
        }
    }
}
