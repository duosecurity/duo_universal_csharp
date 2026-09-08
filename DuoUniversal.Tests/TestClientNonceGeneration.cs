// SPDX-FileCopyrightText: 2026 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Linq;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestClientNonceGeneration
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        [TestCase(1)]
        [TestCase(Client.MINIMUM_NONCE_LENGTH - 1)]
        [TestCase(Client.MAXIMUM_NONCE_LENGTH + 1)]
        [TestCase(1000000000)]
        public void TestInvalidLength(int length)
        {
            Assert.Throws<DuoException>(() => Client.GenerateNonce(length));
        }

        [Test]
        [TestCase(Client.MINIMUM_NONCE_LENGTH)]
        [TestCase(Client.DEFAULT_NONCE_LENGTH)]
        [TestCase(Client.MAXIMUM_NONCE_LENGTH)]
        public void TestSuccess(int length)
        {
            string nonce = Client.GenerateNonce(length);
            Assert.Multiple(() =>
            {
                Assert.AreEqual(length, nonce.Length, "String was unexpected length.");
                Assert.IsTrue(nonce.All(c => char.IsLetterOrDigit(c)), "String contained a character that was not a letter or digit.");
            });
        }

        [Test]
        public void TestDefaultLength()
        {
            string nonce = Client.GenerateNonce();
            Assert.Multiple(() =>
            {
                Assert.AreEqual(Client.DEFAULT_NONCE_LENGTH, nonce.Length, "String was unexpected length.");
                Assert.IsTrue(nonce.All(c => char.IsLetterOrDigit(c)), "String contained a character that was not a letter or digit.");
            });
        }

        [Test]
        public void TestNoncesAreNotRepeated()
        {
            Assert.AreNotEqual(Client.GenerateNonce(), Client.GenerateNonce());
        }

        // The bounds below are the lengths the Duo OIDC Auth API documents for the nonce, asserted as
        // literals so that changing the client's constants cannot silently drift from the API contract.
        // See https://duo.com/docs/oauthapi
        [Test]
        [TestCase(16)]
        [TestCase(1024)]
        public void TestApiDocumentedLengthsAreAccepted(int length)
        {
            Assert.AreEqual(length, Client.GenerateNonce(length).Length);
        }

        [Test]
        [TestCase(15)]
        [TestCase(1025)]
        public void TestLengthsOutsideApiBoundsAreRejected(int length)
        {
            Assert.Throws<DuoException>(() => Client.GenerateNonce(length));
        }
    }
}
