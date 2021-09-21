// SPDX-FileCopyrightText: 2021 Duo Security
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Linq;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestClientStateGeneration
    {
        [SetUp]
        public void Setup()
        {
        }

        [Test]
        [TestCase(1)]
        [TestCase(Client.MINIMUM_STATE_LENGTH - 1)]
        [TestCase(Client.MAXIMUM_STATE_LENGTH + 1)]
        [TestCase(1000000000)]
        public void TestInvalidLength(int length)
        {
            Assert.Throws<DuoException>(() => Client.GenerateState(length));
        }

        [Test]
        [TestCase(Client.MINIMUM_STATE_LENGTH)]
        [TestCase(Client.DEFAULT_STATE_LENGTH)]
        [TestCase(Client.MAXIMUM_STATE_LENGTH)]
        public void TestSuccess(int length)
        {
            string state = Client.GenerateState(length);
            Assert.Multiple(() =>
            {
                Assert.AreEqual(length, state.Length, "String was unexpected length.");
                Assert.IsTrue(state.All(c => char.IsLetterOrDigit(c)), "String contained a character that was not a letter or digit.");
            });
        }

        [Test]
        public void TestDefaultLength()
        {
            string state = Client.GenerateState();
            Assert.Multiple(() =>
            {
                Assert.AreEqual(Client.DEFAULT_STATE_LENGTH, state.Length, "String was unexpected length.");
                Assert.IsTrue(state.All(c => char.IsLetterOrDigit(c)), "String contained a character that was not a letter or digit.");
            });
        }
    }
}
