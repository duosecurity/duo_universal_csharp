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

        private readonly IDictionary<string, string> EMPTY_CLAIMS = new Dictionary<string, string>();

        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void TestCreateSignedJwtSuccess()
        {
            string signedJwt = JwtUtils.CreateSignedJwt(CLIENT_ID, SECRET, AUDIENCE, EMPTY_CLAIMS);
            ValidateToken(signedJwt, SECRET, CLIENT_ID, AUDIENCE, EMPTY_CLAIMS);
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("     ")]
        public void TestCreateSignedJwtBadClientId(string clientId)
        {
            Assert.Throws<ArgumentException>(() => JwtUtils.CreateSignedJwt(clientId, SECRET, AUDIENCE, EMPTY_CLAIMS));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("     ")]
        public void TestCreateSignedJwtBadSecret(string secret)
        {
            Assert.Throws<ArgumentException>(() => JwtUtils.CreateSignedJwt(CLIENT_ID, secret, AUDIENCE, EMPTY_CLAIMS));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("     ")]
        public void TestCreateSignedJwtBadAudience(string audience)
        {
            Assert.Throws<ArgumentException>(() => JwtUtils.CreateSignedJwt(CLIENT_ID, SECRET, audience, EMPTY_CLAIMS));
        }

        [Test]
        public void TestCreateSignedJwtSignatureMismatchFailure()
        {
            string signedJwt = JwtUtils.CreateSignedJwt(CLIENT_ID, SECRET + "wrong", AUDIENCE, EMPTY_CLAIMS);
            Assert.Throws<SignatureVerificationException>(() => ValidateToken(signedJwt, SECRET, CLIENT_ID, AUDIENCE, EMPTY_CLAIMS));
        }

        [Test]
        public void TestAdditionalClaims()
        {
            var additionalClaims = new Dictionary<string, string>  // TODO de-magic-string these
            {
                {"sub", CLIENT_ID},
                {"abc", "xyz"}
            };
            string signedJwt = JwtUtils.CreateSignedJwt(CLIENT_ID, SECRET, AUDIENCE, additionalClaims);
            ValidateToken(signedJwt, SECRET, CLIENT_ID, AUDIENCE, additionalClaims);

        }

        // ----- Token methods that use a different JWT library for testing -----
        // Decode and validate the token, assert the parameters are what we expected
        private static void ValidateToken(string jwt, string secret, string expectedClientId, string expectedAudience, IDictionary<string, string> expectedClaims)
        {
            // This will raise an exception if, for instance, the signature doesn't validate
            IDictionary<string, string> parameters = JwtBuilder.Create()
                                                               .WithAlgorithm(new HMACSHA512Algorithm())
                                                               .WithSecret(secret)
                                                               .MustVerifySignature()
                                                               .Decode<IDictionary<string, string>>(jwt);
            Assert.AreEqual(expectedClientId, parameters["iss"]);  // TODO de-magic-string these
            Assert.AreEqual(expectedAudience, parameters["aud"]);
            Assert.IsNotEmpty(parameters["jti"]);
            Assert.IsNotEmpty(parameters["iat"]);
            Assert.IsNotEmpty(parameters["nbf"]);
            Assert.IsNotEmpty(parameters["exp"]);

            foreach (KeyValuePair<string, string> claim in expectedClaims)
            {
                Assert.AreEqual(claim.Value, parameters[claim.Key]);
            }
        }
    }
}
