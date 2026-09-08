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
        private const string NONCE = "a nonce of a plausible length";
        // Long enough to pass validation, so that a test using it reaches the comparison against the
        // nonce Duo echoed back rather than stopping at the length check
        private const string WRONG_NONCE = "a different nonce, also plausible";
        // Short enough that ValidateNonce rejects it without any call to Duo
        private const string TOO_SHORT_NONCE = "too short";

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

        [Test]
        public async Task TestNonceSuccess()
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponse(NONCE))));
            IdToken idToken = await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME, NONCE);
            Assert.AreEqual(NONCE, idToken.Nonce);
        }

        // These are rejected by validation before any comparison happens, because they are not
        // acceptable nonces in the first place
        [Test]
        [TestCase("not the nonce")]
        [TestCase("")]
        [TestCase(null)]
        public void TestUnusableNonceIsRejected(string expectedNonce)
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponse(NONCE))));
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME, expectedNonce));
        }

        [Test]
        public void TestNonceMismatch()
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponse(NONCE))));
            var exception = Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME, WRONG_NONCE));
            Assert.That(exception.Message, Does.Contain("nonce does not match"));
        }

        [Test]
        public void TestNonceMissingFromIdToken()
        {
            // Duo did not echo a nonce back, but we asked for one
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponse())));
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME, NONCE));
        }

        [Test]
        public async Task TestUnexpectedNonceIsIgnoredWhenNoneRequested()
        {
            // The two-argument overload does not request a nonce, so it does not check one
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponse(NONCE))));
            IdToken idToken = await client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME);
            Assert.AreEqual(USERNAME, idToken.Username);
        }

        [Test]
        public async Task TestSamlResponseNonceSuccess()
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponseWithSamlResponse(NONCE))));
            string samlResponse = await client.ExchangeAuthorizationCodeForSamlResponse(CODE, USERNAME, NONCE);
            Assert.NotNull(samlResponse);
        }

        [Test]
        public void TestSamlResponseNonceMismatch()
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponseWithSamlResponse(NONCE))));
            Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeForSamlResponse(CODE, USERNAME, WRONG_NONCE));
        }

        // The SAML flow should say what actually went wrong, the same as the Id Token flow does, rather
        // than reporting a generic failure and leaving the reason in an inner exception
        [Test]
        public void TestSamlResponseNonceMismatchReportsTheNonce()
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponseWithSamlResponse(NONCE))));
            var exception = Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeForSamlResponse(CODE, USERNAME, WRONG_NONCE));
            Assert.That(exception.Message, Does.Contain("nonce does not match"));
        }

        [Test]
        public void TestSamlResponseUsernameMismatchReportsTheUsername()
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponseWithSamlResponse())));
            var exception = Assert.ThrowsAsync<DuoException>(async () => await client.ExchangeAuthorizationCodeForSamlResponse(CODE, "not username"));
            Assert.That(exception.Message, Does.Contain("username does not match"));
        }

        // The next two tests pin down a subtlety of how the overloads above are put together.  The public
        // overloads are not themselves async; they only hand off to a private async core, and the nonce is
        // validated inside that core.  That means a bad nonce arrives as a faulted Task, which is what a
        // caller of any Task-returning method expects.
        //
        // Moving ValidateNonce up into a public overload, to fail fast, would look harmless and would keep
        // every other test in this file passing, but it would throw at the call site instead, before the
        // caller ever holds a Task.  That breaks anyone who starts the exchange and awaits it later:
        //
        //     var task = client.ExchangeAuthorizationCodeFor2faResult(code, user, nonce);
        //     DoSomeOtherWork();   // a synchronous throw escapes from the line above, not from here
        //     var token = await task;
        //
        // It would equally break passing the call to Task.WhenAll.  Making the public overloads async again
        // would also be a fix, since an async method captures such a throw into its Task; either way, this
        // is the behaviour that has to hold.
        [Test]
        public void TestInvalidNonceFaultsTheTaskInsteadOfThrowingAtTheCallSite()
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponse(NONCE))));

            Task<IdToken> task = null;
            Assert.DoesNotThrow(() => task = client.ExchangeAuthorizationCodeFor2faResult(CODE, USERNAME, TOO_SHORT_NONCE),
                                "The nonce was rejected at the call site instead of through the returned Task");
            Assert.ThrowsAsync<DuoException>(async () => await task);
        }

        [Test]
        public void TestInvalidNonceFaultsTheTaskInsteadOfThrowingAtTheCallSiteForSamlResponse()
        {
            var client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(GoodApiResponseWithSamlResponse(NONCE))));

            Task<string> task = null;
            Assert.DoesNotThrow(() => task = client.ExchangeAuthorizationCodeForSamlResponse(CODE, USERNAME, TOO_SHORT_NONCE),
                                "The nonce was rejected at the call site instead of through the returned Task");
            Assert.ThrowsAsync<DuoException>(async () => await task);
        }

        private static string GoodApiResponse(string nonce = null)
        {
            var responseValues = new Dictionary<string, string>
            {
                {"access_token", "access token"},
                {"expires_in", "1"},
                {"id_token", CreateTokenJwt(nonce: nonce)},
                {"token_type", "Bearer"}
            };
            return JsonSerializer.Serialize(responseValues);
        }

        private static string GoodApiResponseWithSamlResponse(string nonce = null)
        {
            var responseValues = new Dictionary<string, string>
            {
                {"access_token", "access token"},
                {"expires_in", "1"},
                {"id_token", CreateTokenJwt(nonce: nonce)},
                {"token_type", "Bearer"},
                {"saml_response", "saml_response"}
            };
            return JsonSerializer.Serialize(responseValues);
        }
    }
}
