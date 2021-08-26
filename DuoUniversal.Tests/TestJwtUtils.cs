using System;
using System.Collections.Generic;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Exceptions;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestJwtUtils
    {

        private const string SECRET = "abcdefghijlkmnopqrstuvwxyzABCDEFGHIJKLMN";

        private const string CLIENT_ID = "abc";
        private const string AUDIENCE = "xyz";

        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void TestCreateSignedJwtSuccess()
        {
            string signedJwt = JwtUtils.CreateSignedJwt(CLIENT_ID, SECRET, AUDIENCE);
            ValidateToken(signedJwt, SECRET, CLIENT_ID, AUDIENCE);
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("     ")]
        public void TestCreateSignedJwtBadClientId(string clientId)
        {
            Assert.Throws<ArgumentException>(() => JwtUtils.CreateSignedJwt(clientId, SECRET, AUDIENCE));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("     ")]
        public void TestCreateSignedJwtBadSecret(string secret)
        {
            Assert.Throws<ArgumentException>(() => JwtUtils.CreateSignedJwt(CLIENT_ID, secret, AUDIENCE));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("     ")]
        public void TestCreateSignedJwtBadAudience(string audience)
        {
            Assert.Throws<ArgumentException>(() => JwtUtils.CreateSignedJwt(CLIENT_ID, SECRET, audience));
        }

        [Test]
        public void TestCreateSignedJwtSignatureMismatchFailure()
        {
            string signedJwt = JwtUtils.CreateSignedJwt(CLIENT_ID, SECRET + "wrong", AUDIENCE);
            Assert.Throws<SignatureVerificationException>(() => ValidateToken(signedJwt, SECRET, CLIENT_ID, AUDIENCE));
        }

        // ----- Token methods that use a different JWT library for testing -----
        // Decode and validate the token, assert the parameters are what we expected
        private static void ValidateToken(string jwt, string secret, string expectedClientId, string expectedAudience)
        {
            // This will raise an exception if, for instance, the signature doesn't validate
            IDictionary<string, string> parameters = JwtBuilder.Create()
                                                               .WithAlgorithm(new HMACSHA512Algorithm())
                                                               .WithSecret(secret)
                                                               .MustVerifySignature()
                                                               .Decode<IDictionary<string, string>>(jwt);
            Assert.AreEqual(expectedClientId, parameters["iss"]);
            Assert.AreEqual(expectedClientId, parameters["sub"]);
            Assert.AreEqual(expectedAudience, parameters["aud"]);
            Assert.IsNotEmpty(parameters["jti"]);
            Assert.IsNotEmpty(parameters["iat"]);
            Assert.IsNotEmpty(parameters["nbf"]);
            Assert.IsNotEmpty(parameters["exp"]);
        }
    }
}
