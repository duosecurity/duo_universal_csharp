// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Collections.Generic;
using System.Text.Json;
using JWT.Algorithms;
using JWT.Builder;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestGenerateAuthUrl : ClientTestBase
    {
        private readonly string STATE = new('a', Client.DEFAULT_STATE_LENGTH);
        private readonly string NONCE = new('b', Client.DEFAULT_NONCE_LENGTH);

        private Client client;
        [SetUp]
        public void Setup()
        {
            client = new ClientBuilder(CLIENT_ID, CLIENT_SECRET, API_HOST, REDIRECT_URI).Build();
        }

        [Test]
        [TestCase(USERNAME)]
        [TestCase("I iz a user")]
        [TestCase("user@foo.bar")]
        public void TestSuccess(string username)
        {
            string authUri = client.GenerateAuthUri(username, STATE);
            Assert.True(Uri.IsWellFormedUriString(authUri, UriKind.Absolute));
            Assert.True(authUri.StartsWith($"https://{API_HOST}"));
        }

        [Test]
        [TestCase(USERNAME)]
        [TestCase("I iz a user")]
        [TestCase("user@foo.bar")]
        public void TestSuccessWithIssuer(string username)
        {
            Client clientWithIssuer = new ClientBuilder(CLIENT_ID, CLIENT_SECRET, API_HOST, REDIRECT_URI).UseAudienceForSamlResponse("http://issuer").Build();
            string authUri = clientWithIssuer.GenerateAuthUri(username, STATE);
            Assert.True(Uri.IsWellFormedUriString(authUri, UriKind.Absolute));
            Assert.True(authUri.StartsWith($"https://{API_HOST}"));
        }

        [Test]
        [TestCase("  ")]
        public void TestInvalidIssuer(string issuer)
        {
            Client clientWithIssuer = new ClientBuilder(CLIENT_ID, CLIENT_SECRET, API_HOST, REDIRECT_URI).UseAudienceForSamlResponse(issuer).Build();
            Assert.Throws<DuoException>(() => clientWithIssuer.GenerateAuthUri("username", STATE));
        }

        [Test]
        [TestCase(null)]
        public void TestNullIssuer(string issuer)
        {
            Client clientWithIssuer = new ClientBuilder(CLIENT_ID, CLIENT_SECRET, API_HOST, REDIRECT_URI).UseAudienceForSamlResponse(issuer).Build();
            string authUri = clientWithIssuer.GenerateAuthUri("username", STATE);
            Assert.True(Uri.IsWellFormedUriString(authUri, UriKind.Absolute));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("         ")]
        public void TestInvalidUsername(string username)
        {
            Assert.Throws<DuoException>(() => client.GenerateAuthUri(username, STATE));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("          ")]
        public void TestInvalidState(string state)
        {
            Assert.Throws<DuoException>(() => client.GenerateAuthUri(USERNAME, state));
        }

        [Test]
        public void TestShortStateFailure()
        {
            var shortState = new string('z', Client.MINIMUM_STATE_LENGTH - 1);
            Assert.Throws<DuoException>(() => client.GenerateAuthUri(USERNAME, shortState));
        }

        [Test]
        public void TestLongStateFailure()
        {
            var longState = new string('z', Client.MAXIMUM_STATE_LENGTH + 1);
            Assert.Throws<DuoException>(() => client.GenerateAuthUri(USERNAME, longState));
        }

        [Test]
        public void TestNonceIsSentInTheRequestJwt()
        {
            string authUri = client.GenerateAuthUri(USERNAME, STATE, NONCE);
            Assert.AreEqual(NONCE, RequestClaims(authUri)[Labels.NONCE].GetString());
        }

        [Test]
        public void TestNonceIsAbsentWhenNotRequested()
        {
            string authUri = client.GenerateAuthUri(USERNAME, STATE);
            Assert.IsFalse(RequestClaims(authUri).ContainsKey(Labels.NONCE));
        }

        [Test]
        public void TestSuccessWithNonce()
        {
            string authUri = client.GenerateAuthUri(USERNAME, STATE, NONCE);
            Assert.True(Uri.IsWellFormedUriString(authUri, UriKind.Absolute));
            Assert.True(authUri.StartsWith($"https://{API_HOST}"));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("          ")]
        public void TestInvalidNonce(string nonce)
        {
            Assert.Throws<DuoException>(() => client.GenerateAuthUri(USERNAME, STATE, nonce));
        }

        [Test]
        public void TestShortNonceFailure()
        {
            var shortNonce = new string('z', Client.MINIMUM_NONCE_LENGTH - 1);
            Assert.Throws<DuoException>(() => client.GenerateAuthUri(USERNAME, STATE, shortNonce));
        }

        [Test]
        public void TestLongNonceFailure()
        {
            var longNonce = new string('z', Client.MAXIMUM_NONCE_LENGTH + 1);
            Assert.Throws<DuoException>(() => client.GenerateAuthUri(USERNAME, STATE, longNonce));
        }

        // 16 is the shortest nonce the Duo OIDC Auth API accepts; asserted as a literal so the client
        // cannot drift from the documented contract.  See https://duo.com/docs/oauthapi
        [Test]
        public void TestApiMinimumLengthNonceIsSentInTheRequestJwt()
        {
            var shortestValidNonce = new string('n', 16);
            string authUri = client.GenerateAuthUri(USERNAME, STATE, shortestValidNonce);
            Assert.AreEqual(shortestValidNonce, RequestClaims(authUri)[Labels.NONCE].GetString());
        }

        // The claim names below are spelled out as literals rather than referred to through Labels, so
        // that a typo in a Labels constant is a test failure instead of something Duo silently ignores.
        // See https://duo.com/docs/oauthapi

        [Test]
        public void TestDestAppNameIsSentInTheRequestJwt()
        {
            var options = new AuthUriOptions(USERNAME, STATE) { DestAppName = "Acme VPN" };
            string authUri = client.GenerateAuthUri(options);
            Assert.AreEqual("Acme VPN", RequestClaims(authUri)["dest_app_name"].GetString());
        }

        [Test]
        public void TestDestAppIdIsSentInTheRequestJwt()
        {
            var options = new AuthUriOptions(USERNAME, STATE) { DestAppId = "vpn-prod-1" };
            string authUri = client.GenerateAuthUri(options);
            Assert.AreEqual("vpn-prod-1", RequestClaims(authUri)["dest_app_id"].GetString());
        }

        [Test]
        public void TestDisplayUsernameIsSentInTheRequestJwt()
        {
            var options = new AuthUriOptions(USERNAME, STATE) { DisplayUsername = "a.smith@acme.com" };
            string authUri = client.GenerateAuthUri(options);
            Assert.AreEqual("a.smith@acme.com", RequestClaims(authUri)["display_username"].GetString());
        }

        // Only the name shown to the user changes; the user Duo actually authenticates is still the username
        [Test]
        public void TestDisplayUsernameDoesNotChangeWhoIsAuthenticated()
        {
            var options = new AuthUriOptions(USERNAME, STATE) { DisplayUsername = "someone.else@acme.com" };
            string authUri = client.GenerateAuthUri(options);
            Assert.AreEqual(USERNAME, RequestClaims(authUri)[Labels.DUO_UNAME].GetString());
        }

        [Test]
        public void TestMaxAgeIsSentInTheRequestJwt()
        {
            var options = new AuthUriOptions(USERNAME, STATE) { MaxAge = 3600 };
            string authUri = client.GenerateAuthUri(options);
            Assert.AreEqual(3600, RequestClaims(authUri)["max_age"].GetInt32());
        }

        // Duo documents max_age as a number.  Every other claim this client sends is a string, so it
        // would be easy to send "3600" instead and have Duo reject or ignore it.
        [Test]
        public void TestMaxAgeIsSentAsANumberNotAString()
        {
            var options = new AuthUriOptions(USERNAME, STATE) { MaxAge = 3600 };
            string authUri = client.GenerateAuthUri(options);
            Assert.AreEqual(JsonValueKind.Number, RequestClaims(authUri)["max_age"].ValueKind);
        }

        // Zero forces interactive reauthentication rather than meaning "no limit", so it has to survive
        // any check that would mistake it for an unset value
        [Test]
        public void TestMaxAgeOfZeroIsSent()
        {
            var options = new AuthUriOptions(USERNAME, STATE) { MaxAge = 0 };
            string authUri = client.GenerateAuthUri(options);
            Assert.AreEqual(0, RequestClaims(authUri)["max_age"].GetInt32());
        }

        // The enum member is Login but Duo expects the lowercase "login", so the value Duo sees matters
        // more here than the name the caller writes
        [Test]
        public void TestPromptIsSentInTheRequestJwt()
        {
            var options = new AuthUriOptions(USERNAME, STATE) { Prompt = AuthPrompt.Login };
            string authUri = client.GenerateAuthUri(options);
            Assert.AreEqual("login", RequestClaims(authUri)["prompt"].GetString());
        }

        // AuthPrompt has a single member today, so the client can send "login" whenever a prompt is set.
        // This fails the day a second member is added without teaching the client how to spell it, rather
        // than letting the new value go to Duo as "login".
        [Test]
        public void TestEveryAuthPromptValueIsSentAsADistinctValue()
        {
            var values = Enum.GetValues(typeof(AuthPrompt));
            var sent = new HashSet<string>();
            foreach (AuthPrompt prompt in values)
            {
                var options = new AuthUriOptions(USERNAME, STATE) { Prompt = prompt };
                sent.Add(RequestClaims(client.GenerateAuthUri(options))["prompt"].GetString());
            }
            Assert.AreEqual(values.Length, sent.Count, "Two AuthPrompt values are sent to Duo as the same string");
        }

        // Duo tells an absent claim apart from one present with an empty value, so anything the caller
        // did not set has to stay out of the request rather than going along as null or ""
        [Test]
        public void TestUnsetOptionsAreLeftOutOfTheRequestJwt()
        {
            var claims = RequestClaims(client.GenerateAuthUri(new AuthUriOptions(USERNAME, STATE)));
            Assert.Multiple(() =>
            {
                Assert.IsFalse(claims.ContainsKey(Labels.NONCE), "nonce");
                Assert.IsFalse(claims.ContainsKey("dest_app_name"), "dest_app_name");
                Assert.IsFalse(claims.ContainsKey("dest_app_id"), "dest_app_id");
                Assert.IsFalse(claims.ContainsKey("display_username"), "display_username");
                Assert.IsFalse(claims.ContainsKey("max_age"), "max_age");
                Assert.IsFalse(claims.ContainsKey("prompt"), "prompt");
            });
        }

        [Test]
        public void TestNullOptionsThrowsDuoException()
        {
            Assert.Throws<DuoException>(() => client.GenerateAuthUri((AuthUriOptions)null));
        }

        /// <summary>
        /// Pull the embedded request JWT out of an auth URI and decode its claims, verifying the
        /// signature with an independent JWT library.
        ///
        /// Claims come back as JsonElement rather than string so that a test can tell what JSON type
        /// a claim was sent as; Duo documents some of them as numbers rather than strings.
        /// </summary>
        private static IDictionary<string, JsonElement> RequestClaims(string authUri)
        {
            var query = System.Web.HttpUtility.ParseQueryString(new Uri(authUri).Query);
            string payload = JwtBuilder.Create()
                                       .WithAlgorithm(new HMACSHA512Algorithm())
                                       .WithSecret(CLIENT_SECRET)
                                       .MustVerifySignature()
                                       .Decode(query[Labels.REQUEST]);
            return JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payload);
        }
    }
}
