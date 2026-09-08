// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Collections.Generic;
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
            Assert.AreEqual(NONCE, RequestClaims(authUri)[Labels.NONCE]);
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
            Assert.AreEqual(shortestValidNonce, RequestClaims(authUri)[Labels.NONCE]);
        }

        /// <summary>
        /// Pull the embedded request JWT out of an auth URI and decode its claims, verifying the
        /// signature with an independent JWT library
        /// </summary>
        private static IDictionary<string, string> RequestClaims(string authUri)
        {
            var query = System.Web.HttpUtility.ParseQueryString(new Uri(authUri).Query);
            return JwtBuilder.Create()
                             .WithAlgorithm(new HMACSHA512Algorithm())
                             .WithSecret(CLIENT_SECRET)
                             .MustVerifySignature()
                             .Decode<IDictionary<string, string>>(query[Labels.REQUEST]);
        }
    }
}
