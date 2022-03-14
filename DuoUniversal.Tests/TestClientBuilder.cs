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

        private static string GetDefaultUA()
        {
            var client = BasicBuilder().Build();
            return client.HttpClient.DefaultRequestHeaders.UserAgent.ToString();
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

        [Test]
        public void TestDefaultUserAgent()
        {
            var ua = GetDefaultUA();
            Assert.True(ua.Contains(Client.DUO_UNIVERSAL_CSHARP));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("    ")]
        [TestCase("I am the very model of a modern Major-General")] // simple string
        [TestCase("[OS/2 Warp 0.0.0.1] (foo/bar 1.0.3) {flim/flam 0.5qx}")] // product/version pairs
        [TestCase("(ABC) ([WX{Y}]Z)")] // nesting balanced brackets
        [TestCase("/=/=/=/= !@#$%^&*()")] // special chars
        public void TestUserAgentAddition(string additionalUserAgentString)
        {
            var defaultUA = GetDefaultUA();

            var client = BasicBuilder().AppendToUserAgent(additionalUserAgentString).Build();
            var ua = client.HttpClient.DefaultRequestHeaders.UserAgent.ToString();
            if (!string.IsNullOrWhiteSpace(additionalUserAgentString))
            {
                Assert.True(ua.Contains(additionalUserAgentString));
            }
            else
            {
                Assert.AreEqual(ua, defaultUA);
            }
        }

        [Test]
        [TestCase(null, null)]
        [TestCase(null, "")]
        [TestCase("", null)]
        [TestCase("", "")]
        [TestCase("  ", "  ")]
        [TestCase("abc", "123")]
        public void TestUserAgentCustomApp(string customApp, string customVersion)
        {
            var defaultUA = GetDefaultUA();

            var client = BasicBuilder().CustomizeUserAgentApp(customApp, customVersion).Build();
            var ua = client.HttpClient.DefaultRequestHeaders.UserAgent.ToString();
            if (!string.IsNullOrWhiteSpace(customApp) && !string.IsNullOrWhiteSpace(customVersion))
            {
                Assert.True(ua.Contains(customApp));
                Assert.True(ua.Contains(customVersion));
            }
            else
            {
                Assert.AreEqual(ua, defaultUA);
            }
        }

        [Test]
        [TestCase("abc", "123", "additional")]
        public void TestFullUserAgentCustomization(string customApp, string customVersion, string additional)
        {
            var client = BasicBuilder().CustomizeUserAgentApp(customApp, customVersion).AppendToUserAgent(additional).Build();
            var ua = client.HttpClient.DefaultRequestHeaders.UserAgent.ToString();

            Assert.True(ua.Contains(customApp));
            Assert.True(ua.Contains(customVersion));
            Assert.True(ua.Contains(additional));
        }

        [Test]
        [TestCase("((())")]  // Unbalanced parenthesis are invalid
        public void TestInvalidUserAgent(string additionalUserAgentString)
        {
            Assert.Throws<DuoException>(() =>
            {
                BasicBuilder().AppendToUserAgent(additionalUserAgentString).Build();
            });
        }
    }
}
