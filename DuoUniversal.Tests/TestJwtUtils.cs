// SPDX-FileCopyrightText: 2021 Duo Security
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Collections.Generic;
using JWT.Algorithms;
using JWT.Builder;
using JWT.Exceptions;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestJwtUtils : TestBase
    {
        private readonly IDictionary<string, string> EMPTY_CLAIMS = new Dictionary<string, string>();

        [SetUp]
        public void Setup()
        {
        }

        [Test]
        public void TestCreateSignedJwtSuccess()
        {
            string signedJwt = JwtUtils.CreateSignedJwt(CLIENT_ID, CLIENT_SECRET, API_HOST, EMPTY_CLAIMS);
            ValidateToken(signedJwt, CLIENT_SECRET, CLIENT_ID, API_HOST, EMPTY_CLAIMS);
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("     ")]
        public void TestCreateSignedJwtBadClientId(string clientId)
        {
            Assert.Throws<DuoException>(() => JwtUtils.CreateSignedJwt(clientId, CLIENT_SECRET, API_HOST, EMPTY_CLAIMS));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("     ")]
        public void TestCreateSignedJwtBadSecret(string secret)
        {
            Assert.Throws<DuoException>(() => JwtUtils.CreateSignedJwt(CLIENT_ID, secret, API_HOST, EMPTY_CLAIMS));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("     ")]
        public void TestCreateSignedJwtBadAudience(string audience)
        {
            Assert.Throws<DuoException>(() => JwtUtils.CreateSignedJwt(CLIENT_ID, CLIENT_SECRET, audience, EMPTY_CLAIMS));
        }

        [Test]
        public void TestCreateSignedJwtSignatureMismatchFailure()
        {
            string signedJwt = JwtUtils.CreateSignedJwt(CLIENT_ID, CLIENT_SECRET + "wrong", API_HOST, EMPTY_CLAIMS);
            Assert.Throws<SignatureVerificationException>(() => ValidateToken(signedJwt, CLIENT_SECRET, CLIENT_ID, API_HOST, EMPTY_CLAIMS));
        }

        [Test]
        public void TestCreateAdditionalClaims()
        {
            var additionalClaims = new Dictionary<string, string>
            {
                {Labels.SUB, CLIENT_ID},
                {"abc", "xyz"}
            };
            string signedJwt = JwtUtils.CreateSignedJwt(CLIENT_ID, CLIENT_SECRET, API_HOST, additionalClaims);
            ValidateToken(signedJwt, CLIENT_SECRET, CLIENT_ID, API_HOST, additionalClaims);
        }

        [Test]
        public void TestValidateSuccess()
        {
            string jwt = CreateJwt();
            Assert.DoesNotThrow(() => JwtUtils.ValidateJwt(jwt, CLIENT_ID, CLIENT_SECRET, API_HOST));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("         ")]
        [TestCase("I'm not a JWT!")]
        [TestCase("not_enough_dots")]
        [TestCase("still_not.enough_dots")]
        public void TestValidateNonJwtThrows(string nonJwt)
        {
            Assert.Throws<DuoException>(() => JwtUtils.ValidateJwt(nonJwt, CLIENT_ID, CLIENT_SECRET, API_HOST));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("wrong" + CLIENT_ID)]
        public void TestValidateWrongAudience(string audience)
        {
            string jwt = CreateJwt();
            Assert.Throws<DuoException>(() => JwtUtils.ValidateJwt(jwt, audience, CLIENT_SECRET, API_HOST));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("wrong" + API_HOST)]
        public void TestValidateWrongIssuer(string issuer)
        {
            string jwt = CreateJwt();
            Assert.Throws<DuoException>(() => JwtUtils.ValidateJwt(jwt, CLIENT_ID, CLIENT_SECRET, issuer));
        }

        [Test]
        [TestCase(null)]
        [TestCase("")]
        [TestCase("abc123")]
        [TestCase("wrong" + CLIENT_SECRET)]
        public void TestValidateWrongSecret(string secret)
        {
            string jwt = CreateJwt();
            Assert.Throws<DuoException>(() => JwtUtils.ValidateJwt(jwt, CLIENT_ID, secret, API_HOST));
        }

        [Test]
        public void TestValidateBeforeIat()
        {
            long skew = 300;  // default skew
            long now = ((DateTimeOffset)DateTime.Now).ToUnixTimeSeconds();
            long iat = now + (2 * skew);
            long exp = iat + skew;

            // Now IAT/NBF is too far in the future
            string jwt = CreateJwt(iat, exp);
            Assert.Throws<DuoException>(() => JwtUtils.ValidateJwt(jwt, CLIENT_ID, CLIENT_SECRET, API_HOST));
        }

        [Test]
        public void TestValidateAfterExp()
        {
            long skew = 300;  // default skew
            long now = ((DateTimeOffset)DateTime.Now).ToUnixTimeSeconds();
            long exp = now - (skew * 2);
            long iat = exp - skew;

            // Now EXP is too far in the past
            string jwt = CreateJwt(iat, exp);
            Assert.Throws<DuoException>(() => JwtUtils.ValidateJwt(jwt, CLIENT_ID, CLIENT_SECRET, API_HOST));
        }

        [Test]
        public void TestValidateIatWithinSkew()
        {
            long skew = 300;  // default skew
            long now = ((DateTimeOffset)DateTime.Now).ToUnixTimeSeconds();
            long iat = now + (skew / 2);
            long exp = iat + skew;

            // Now IAT/NBF is slightly in the future, but within the skew
            string jwt = CreateJwt(iat, exp);
            Assert.DoesNotThrow(() => JwtUtils.ValidateJwt(jwt, CLIENT_ID, CLIENT_SECRET, API_HOST));
        }

        [Test]
        public void TestValidateExpWithinSkew()
        {
            long skew = 300;  // default skew
            long now = ((DateTimeOffset)DateTime.Now).ToUnixTimeSeconds();
            long exp = now - (skew / 2);
            long iat = exp - skew;

            // Now EXP is slightly in the past, but within the skew
            string jwt = CreateJwt(iat, exp);
            Assert.DoesNotThrow(() => JwtUtils.ValidateJwt(jwt, CLIENT_ID, CLIENT_SECRET, API_HOST));
        }

        [Test]
        public void TestValidateNbfAfterExp()
        {
            long now = ((DateTimeOffset)DateTime.Now).ToUnixTimeSeconds();
            long iat = now + 10;
            long exp = now - 10;

            // IAT/NBF and EXP are within skew, but EXP is _before_ IAT, which is invalid
            string jwt = CreateJwt(iat, exp);
            Assert.Throws<DuoException>(() => JwtUtils.ValidateJwt(jwt, CLIENT_ID, CLIENT_SECRET, API_HOST));
        }

        [Test]
        public void TestValidateUnacceptableSigningAlgorithm()
        {
            string jwt = CreateJwt(new HMACSHA256Algorithm());
            Assert.Throws<DuoException>(() => JwtUtils.ValidateJwt(jwt, CLIENT_ID, CLIENT_SECRET, API_HOST));
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
            Assert.AreEqual(expectedClientId, parameters[Labels.ISS]);
            Assert.AreEqual(expectedAudience, parameters[Labels.AUD]);
            Assert.IsNotEmpty(parameters[Labels.JTI]);
            Assert.IsNotEmpty(parameters[Labels.IAT]);
            Assert.IsNotEmpty(parameters[Labels.NBF]);
            Assert.IsNotEmpty(parameters[Labels.EXP]);

            foreach (KeyValuePair<string, string> claim in expectedClaims)
            {
                Assert.AreEqual(claim.Value, parameters[claim.Key]);
            }
        }

        // Create a sample token for testing validation.  This simulates a token sent to the client from Duo
        internal static string CreateJwt()
        {
            return CreateJwt(new HMACSHA512Algorithm());
        }

        private static string CreateJwt(IJwtAlgorithm algorithm)
        {
            long iat = ((DateTimeOffset)DateTime.Now).ToUnixTimeSeconds();
            long exp = iat + 300; // 5 minutes later

            return CreateJwt(iat, exp, algorithm);
        }

        private static string CreateJwt(long iat, long exp)
        {
            return CreateJwt(iat, exp, new HMACSHA512Algorithm());
        }

        private static string CreateJwt(long iat, long exp, IJwtAlgorithm algorithm)
        {
            return JwtBuilder.Create()
                             .WithAlgorithm(algorithm)
                             .WithSecret(CLIENT_SECRET)
                             .AddClaim(Labels.ISS, API_HOST)
                             .AddClaim(Labels.SUB, "subject")
                             .AddClaim(Labels.AUD, CLIENT_ID)
                             .AddClaim(Labels.IAT, iat)
                             .AddClaim(Labels.NBF, iat)
                             .AddClaim(Labels.EXP, exp)
                             .AddClaim(Labels.PREFERRED_USERNAME, USERNAME)
                             .Encode();
        }
    }
}
