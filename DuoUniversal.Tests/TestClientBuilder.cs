// SPDX-FileCopyrightText: 2021 Duo Security
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestClientBuilder : ClientTestBase
    {
        [SetUp]
        public void Setup()
        {
        }

        private static ClientBuilder BasicBuilder()
        {
            return new ClientBuilder(CLIENT_ID, CLIENT_SECRET, API_HOST, REDIRECT_URI);
        }

        [Test]
        public void TestBasicBuilder()
        {
            var client = BasicBuilder().Build();
            Assert.AreEqual(client.ClientId, CLIENT_ID);
            Assert.AreEqual(client.ClientSecret, CLIENT_SECRET);
            Assert.AreEqual(client.ApiHost, API_HOST);
            Assert.AreEqual(client.RedirectUri, REDIRECT_URI);
        }

        [Test]
        [TestCase(true, true)]
        [TestCase(false, false)]
        public void TestUseDuoCodeAttribute(bool shouldSpecify, bool expectedValue)
        {
            var builder = BasicBuilder();
            if (shouldSpecify)
            {
                builder.UseDuoCodeAttribute();
            }
            var client = builder.Build();

            Assert.AreEqual(client.UseDuoCodeAttribute, expectedValue);
        }
    }
}
