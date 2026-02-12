// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
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
                .ConfigureAppConfiguration((hostingContext, config) =>
                {
                    var envFile = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), ".env");
                    if (System.IO.File.Exists(envFile))
                    {
                        foreach (var line in System.IO.File.ReadAllLines(envFile))
                        {
                            var parts = line.Split('=', 2, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length == 2)
                            {
                                // Map DUO_CLIENT_ID or Duo__ClientId to Duo:ClientId
                                var key = parts[0].Trim();
                                if (key.StartsWith("DUO_", StringComparison.OrdinalIgnoreCase))
                                {
                                    key = key.Substring(4);
                                }
                                else if (key.StartsWith("Duo__", StringComparison.OrdinalIgnoreCase))
                                {
                                    key = key.Substring(5);
                                }

                                // Convert CLIENT_ID to ClientId (very basic TitleCase)
                                var words = key.Split('_');
                                for (int i = 0; i < words.Length; i++)
                                {
                                    if (words[i].Length > 0)
                                        words[i] = char.ToUpper(words[i][0]) + words[i].Substring(1).ToLower();
                                }
                                key = "Duo:" + string.Join("", words);
                                
                                var value = parts[1].Trim();
                                config.AddInMemoryCollection(new[] { new System.Collections.Generic.KeyValuePair<string, string>(key, value) });
                            }
                        }
                    }
                })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}
