// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using NUnit.Framework;

namespace DuoUniversal.Tests
{
    [TestFixture]
    public class TestHealthCheck : ClientTestBase
    {
        private const string HEALTHY_CONTENT = @"{""stat"": ""OK"", ""response"": {""timestamp"": ""1629837896""}}";
        private const string UNHEALTHY_CONTENT = @"{""stat"": ""FAIL"", ""code"": ""40301"", ""timestamp"": ""1629837896"", ""message"": ""ohnoes"", ""message_detail"": ""ohnoes""}";

        [Test]
        public async Task TestSuccess()
        {
            Client client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(HEALTHY_CONTENT)));
            bool healthy = await client.DoHealthCheck();
            Assert.True(healthy);
        }

        [Test]
        public async Task TestHttpException()
        {
            Client client = MakeClient(new HttpExcepter());
            bool healthy = await client.DoHealthCheck();
            Assert.False(healthy);
        }

        [Test]
        public async Task TestUnhealthyStat()
        {
            Client client = MakeClient(new HttpResponder(HttpStatusCode.OK, new StringContent(UNHEALTHY_CONTENT)));
            bool healthy = await client.DoHealthCheck();
            Assert.False(healthy);
        }

        [Test]
        public async Task TestBadStatusCode()
        {
            Client client = MakeClient(new HttpResponder(HttpStatusCode.BadRequest, new StringContent(UNHEALTHY_CONTENT)));
            bool healthy = await client.DoHealthCheck();
            Assert.False(healthy);
        }
    }
}
