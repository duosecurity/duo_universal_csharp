// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DuoUniversal
{

    internal class HealthCheckResponse
    {
        public string Stat { get; set; }
        // Response will only be set if Stat == "OK"
        public HealthCheckSuccessDetail Response { get; set; }
        // These 4 fields will only be set if Stat == "FAIL"
        public int Timestamp { get; set; }
        public int Code { get; set; }
        public string Message { get; set; }
        [JsonPropertyName("message_detail")]
        public string MessageDetail { get; set; }
    }

    internal class HealthCheckSuccessDetail
    {
        public int Timestamp { get; set; }
    }

    internal class TokenResponse
    {
        [JsonPropertyName("id_token")]
        public string IdToken { get; set; }
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }
        [JsonPropertyName("token_type")]
        public string TokenType { get; set; }
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
        [JsonPropertyName("saml_response")]
        public string SamlResponse { get; set; }
    }

    public class IdToken
    {
        // Custom Duo fields
        public AuthContext AuthContext { get; set; }
        public AuthResult AuthResult { get; set; }
        public int AuthTime { get; set; }
        public string Username { get; set; }
        // Standard JWT stuff
        public string Iss { get; set; }
        public DateTime Exp { get; set; }
        public DateTime Iat { get; set; }
        public string Sub { get; set; }
        public string Aud { get; set; }
        public string Nonce { get; set; }
    }

    public class AuthContext
    {
        [JsonPropertyName("access_device")]
        public AccessDevice AccessDevice { get; set; }
        [JsonPropertyName("alias")]
        public string Alias { get; set; }
        [JsonPropertyName("application")]
        public Application Application { get; set; }
        [JsonPropertyName("auth_device")]
        public AuthDevice AuthDevice { get; set; }
        [JsonPropertyName("email")]
        public string Email { get; set; }
        [JsonPropertyName("event_type")]
        public string EventType { get; set; }
        [JsonPropertyName("factor")]
        public string Factor { get; set; }
        [JsonPropertyName("isotimestamp")]
        public string IsoTimestamp { get; set; }
        [JsonPropertyName("ood_software")]
        public string OodSoftware { get; set; }
        [JsonPropertyName("reason")]
        public string Reason { get; set; }
        [JsonPropertyName("result")]
        public string Result { get; set; }
        [JsonPropertyName("timestamp")]
        public int Timestamp { get; set; }
        [JsonPropertyName("trusted_endpoint_status")]
        public string TrustedEndpointStatus { get; set; }
        [JsonPropertyName("txid")]
        public string Txid { get; set; }
        [JsonPropertyName("user")]
        public User User { get; set; }

    }

    public class AccessDevice
    {
        [JsonPropertyName("browser")]
        public string Browser { get; set; }
        [JsonPropertyName("browser_version")]
        public string BrowserVersion { get; set; }
        [JsonPropertyName("flash_version")]
        public string FlashVersion { get; set; }
        [JsonPropertyName("hostname")]
        public string Hostname { get; set; }
        [JsonPropertyName("ip")]
        public string IpAddress { get; set; }
        [JsonPropertyName("is_encryption_enabled")]
        [JsonConverter(typeof(StringifyingConverter))]
        public string IsEncryptionEnabled { get; set; }
        [JsonPropertyName("is_firewall_enabled")]
        [JsonConverter(typeof(StringifyingConverter))]
        public string IsFirewallEnabled { get; set; }
        [JsonPropertyName("is_password_set")]
        [JsonConverter(typeof(StringifyingConverter))]
        public string IsPasswordSet { get; set; }
        [JsonPropertyName("java_version")]
        public string JavaVersion { get; set; }
        [JsonPropertyName("location")]
        public Location Location { get; set; }
        [JsonPropertyName("os")]
        public string OperatingSystem { get; set; }
        [JsonPropertyName("os_version")]
        public string OperatingSystemVersion { get; set; }
    }

    public class Location
    {
        [JsonPropertyName("city")]
        public string City { get; set; }
        [JsonPropertyName("country")]
        public string Country { get; set; }
        [JsonPropertyName("state")]
        public string State { get; set; }
    }

    public class Application
    {
        [JsonPropertyName("key")]
        public string Key { get; set; }
        [JsonPropertyName("name")]
        public string Name { get; set; }
    }

    public class AuthDevice
    {
        [JsonPropertyName("ip")]
        public string IpAddress { get; set; }
        [JsonPropertyName("location")]
        public Location Location { get; set; }
        [JsonPropertyName("name")]
        public string Name { get; set; }
    }

    public class User
    {
        [JsonPropertyName("groups")]
        public List<string> Groups { get; set; }
        [JsonPropertyName("key")]
        public string Key { get; set; }
        [JsonPropertyName("name")]
        public string Name { get; set; }
    }

    public class AuthResult
    {
        [JsonPropertyName("result")]
        public string Result { get; set; }
        [JsonPropertyName("status")]
        public string Status { get; set; }
        [JsonPropertyName("status_msg")]
        public string StatusMsg { get; set; }
    }

    /// <summary>
    /// For certain fields in the API response for an ID Token, Duo can send either true, false, or 'unknown', which we need to parse correctly
    /// </summary>
    internal class StringifyingConverter : JsonConverter<string>
    {
        /// <summary>
        /// Parse the 'special' Duo three-valued boolean into "true", "false", or returns the string Duo sent
        /// </summary>
        /// <returns>a string</returns>
        public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            var rtt = reader.TokenType;
            switch (rtt)
            {
                case JsonTokenType.True:
                    {
                        return "true";
                    }
                case JsonTokenType.False:
                    {
                        return "false";
                    }
                case JsonTokenType.String:
                    {
                        return reader.GetString();
                    }
                default:
                    {
                        return null;
                    }
            }
        }

        /// <summary>
        /// Write the value back to JSON
        /// </summary>
        public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
        {
            writer.WriteStringValue(value);
        }
    }
}
