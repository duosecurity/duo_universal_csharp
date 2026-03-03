// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using System.Linq;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace DuoUniversal.Example
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((hostingContext, configBuilder) =>
                {
                    // Check local directory and parent directory for .env
                    string envPath = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), ".env");
                    if (!System.IO.File.Exists(envPath))
                    {
                        envPath = System.IO.Path.Combine(System.IO.Directory.GetParent(System.IO.Directory.GetCurrentDirectory())?.FullName ?? "", ".env");
                    }

                    if (System.IO.File.Exists(envPath))
                    {
                        Console.WriteLine($"[DEBUG] Loading configuration from: {envPath}");
                        var settings = new System.Collections.Generic.Dictionary<string, string>();
                        
                        foreach (var line in System.IO.File.ReadAllLines(envPath))
                        {
                            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;

                            var parts = line.Split('=', 2, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length == 2)
                            {
                                var key = parts[0].Trim();
                                var value = parts[1].Trim();

                                // Map keys: DUO_CLIENT_ID -> Duo:ClientId
                                if (key.StartsWith("DUO_", StringComparison.OrdinalIgnoreCase))
                                {
                                    var suffix = key.Substring(4);
                                    var words = suffix.Split('_');
                                    for (int i = 0; i < words.Length; i++)
                                    {
                                        if (words[i].Length > 0)
                                            words[i] = char.ToUpper(words[i][0]) + words[i].Substring(1).ToLower();
                                    }
                                    var normalizedKey = "Duo:" + string.Join("", words);
                                    settings[normalizedKey] = value;
                                    Console.WriteLine($"[DEBUG] Mapped {key} to {normalizedKey}");
                                }
                                else
                                {
                                    settings[key] = value;
                                }
                            }
                        }
                        configBuilder.AddInMemoryCollection(settings);
                    }
                    else
                    {
                        Console.WriteLine("[DEBUG] No .env file found.");
                    }
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }

    // Add this helper for Linq Select since we are in a simple file
    internal static class StringExtensions
    {
        public static string ToTitleCase(this string str)
        {
            if (string.IsNullOrEmpty(str)) return str;
            return char.ToUpper(str[0]) + str.Substring(1).ToLower();
        }
    }
}
