// SPDX-FileCopyrightText: 2022 Cisco Systems, Inc. and/or its affiliates
//
// SPDX-License-Identifier: BSD-3-Clause

using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using DuoUniversal.Example.Data;

namespace DuoUniversal.Example
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            // Bind Duo configuration from appsettings.json or Environment Variables
            services.Configure<DuoConfig>(Configuration.GetSection("Duo"));

            // This is one possible way to make a Duo client factory available, there are many other options.
            services.AddSingleton<IDuoClientProvider, DuoClientProvider>();

            services.AddDistributedMemoryCache();
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(60);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
                options.Cookie.Name = ".Duo.Session";
                // Lax is more compatible with IP addresses and untrusted certificates
                // It allows the cookie to be sent during the top-level GET redirect from Duo
                options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
                options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.SameAsRequest;
            }
            );
            services.AddDbContext<AppDbContext>(options =>
                options.UseSqlite(Configuration.GetConnectionString("DefaultConnection")));

            services.AddRazorPages();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, AppDbContext dbContext)
        {
            // Create and seed database
            SeedData.Initialize(dbContext);

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseSession();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
            });
        }
    }

    public interface IDuoClientProvider
    {
        public Client GetDuoClient();
    }

    internal class DuoClientProvider : IDuoClientProvider
    {
        private readonly DuoConfig _config;

        public DuoClientProvider(Microsoft.Extensions.Options.IOptions<DuoConfig> duoConfig)
        {
            _config = duoConfig.Value;
        }

        public Client GetDuoClient()
        {
            if (string.IsNullOrWhiteSpace(_config.ClientId))
            {
                throw new DuoException("A 'Duo:ClientId' configuration value is required (check .env or appsettings.json).");
            }
            if (string.IsNullOrWhiteSpace(_config.ClientSecret))
            {
                throw new DuoException("A 'Duo:ClientSecret' configuration value is required.");
            }
            if (string.IsNullOrWhiteSpace(_config.ApiHost))
            {
                throw new DuoException("A 'Duo:ApiHost' configuration value is required.");
            }
            if (string.IsNullOrWhiteSpace(_config.RedirectUri))
            {
                throw new DuoException("A 'Duo:RedirectUri' configuration value is required.");
            }

            return new ClientBuilder(_config.ClientId, _config.ClientSecret, _config.ApiHost, _config.RedirectUri).Build();
        }
    }
}
