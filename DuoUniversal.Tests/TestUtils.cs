using System;
using System.Linq;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestUtils : TestBase
    {

        [SetUp]
        public void Setup()
        {
        }

        [Test]
        [TestCase(1)]
        [TestCase(10)]
        [TestCase(36)]
        [TestCase(100)]
        public void TestGenerateRandomString(int length)
        {
            string theString = Utils.GenerateRandomString(length);
            Assert.Multiple(() =>
            {
                Assert.AreEqual(length, theString.Length, "String was unexpected length.");
                Assert.IsTrue(theString.All(c => char.IsLetterOrDigit(c)), "String contained a character that was not a letter or digit.");
            });
        }

        [Test]
        public void TestDecode()
        {
            string jwt = CreateTokenJwt();
            IdToken idToken = Utils.DecodeToken(jwt);
            // Assert some values throughout the token
            Assert.AreEqual(USERNAME, idToken.Username);
            Assert.AreEqual(ALLOW, idToken.AuthResult.Result);
            Assert.AreEqual(BROWSER, idToken.AuthContext.AccessDevice.Browser);
            Assert.AreEqual(GEO_STATE, idToken.AuthContext.AccessDevice.Location.State);
            Assert.AreEqual(NAME, idToken.AuthContext.User.Name);
        }

    }
}
