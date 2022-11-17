// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestGenerateAuthUrl : ClientTestBase
    {
        private readonly string STATE = new('a', Client.DEFAULT_STATE_LENGTH);

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
    }
}
