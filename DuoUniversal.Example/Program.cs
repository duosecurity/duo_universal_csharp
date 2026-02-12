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
            LoadEnvFile();
            CreateHostBuilder(args).Build().Run();
        }

        private static void LoadEnvFile()
        {
            var envFile = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), ".env");
            if (System.IO.File.Exists(envFile))
            {
                foreach (var line in System.IO.File.ReadAllLines(envFile))
                {
                    var parts = line.Split('=', 2, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 2)
                    {
                        var key = parts[0].Trim();
                        var value = parts[1].Trim();

                        // Map DUO_ prefixes to Duo__ for ASP.NET naming convention
                        if (key.StartsWith("DUO_", StringComparison.OrdinalIgnoreCase))
                        {
                            var normalizedKey = "Duo__" + string.Join("", key.Substring(4).Split('_').Select(w => char.ToUpper(w[0]) + w.Substring(1).ToLower()));
                            Environment.SetEnvironmentVariable(normalizedKey, value);
                        }
                        else
                        {
                            Environment.SetEnvironmentVariable(key, value);
                        }
                    }
                }
            }
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
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
}
