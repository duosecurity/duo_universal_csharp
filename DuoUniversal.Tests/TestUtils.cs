using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestUtils
    {
        private const string SECRET = "abcdefghijlkmnopqrstuvwxyzABCDEFGHIJKLMN";

        // Some JWT values to test the conversions
        private const string ALLOW = "allow";
        private const string BROWSER = "browser";
        private const string NAME = "name";
        private const string STATE = "state";
        private const string USERNAME = "username";

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
            string jwt = CreateJwtString();
            IdToken idToken = Utils.DecodeToken(jwt);
            // Assert some values throughout the token
            Assert.AreEqual(USERNAME, idToken.Username);
            Assert.AreEqual(ALLOW, idToken.AuthResult.Result);
            Assert.AreEqual(BROWSER, idToken.AuthContext.AccessDevice.Browser);
            Assert.AreEqual(STATE, idToken.AuthContext.AccessDevice.Location.State);
            Assert.AreEqual(NAME, idToken.AuthContext.User.Name);
        }

        internal static string CreateJwtString()
        {
            // Make a representative id token
            var payloadData = new
            {
                // Duo claims
                auth_context = new
                {
                    access_device = new
                    {
                        browser = BROWSER,
                        browser_version = "1.2.3.4",
                        flash_version = "4.3.2.1",
                        hostname = "",  // TODO what type is this?
                        ip = "100.200.100.200",
                        is_encryption_enabled = "unknown",
                        is_firewall_enabled = "unknown",
                        is_password_set = "unknown",
                        java_version = "4.3.2.1",
                        location = new
                        {
                            city = "city",
                            country = "country",
                            state = STATE,
                        },
                        os = "Mac OS X",
                        os_version = "10.15.7",
                        security_agents = "unknown"
                    },
                    alias = "",
                    application = new
                    {
                        key = "DIXXXXXXXXXXXXXXXXXX",
                        name = "Web SDK 4",
                    },
                    auth_device = new
                    {
                        ip = "200.100.200.100",
                        location = new
                        {
                            city = "city",
                            country = "country",
                            state = STATE,
                        },
                        name = "name"
                    },
                    email = "",
                    event_type = "authentication",
                    factor = "duo_push",
                    isotimestamp = "2021-08-30T18:00:00.00000+00:00",
                    ood_software = "TODO", // TODO what type is this?
                    reason = "user_approved",
                    result = "success",
                    timestamp = 1234,
                    trusted_endpoint_status = "unknown",
                    txid = "123456",
                    user = new
                    {
                        groups = new List<string>(),
                        key = "key",
                        name = NAME
                    }
                },
                auth_result = new
                {
                    result = ALLOW,
                    status = "allow",
                    status_msg = "Login successful"
                },
                auth_time = 1234,
                preferred_username = USERNAME,
                // Standard JWT stuff fields (exp, nbf, and iat will be automatically added)
                aud = "audience",
                iss = "issuer",
                sub = "subject",
            };
            string payload = JsonSerializer.Serialize(payloadData);

            return JwtUtils.CreateJwtFromPayload(payload, SECRET);
        }
    }
}
