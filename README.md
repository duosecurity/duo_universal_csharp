# Duo Universal Prompt C# Client

[![Build Status](https://github.com/duosecurity/duo_universal_csharp/workflows/.NET%20CI/badge.svg)](https://github.com/duosecurity/duo_universal_csharp/actions)
[![Issues](https://img.shields.io/github/issues/duosecurity/duo_universal_csharp)](https://github.com/duosecurity/duo_universal_csharp/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/duo_universal_csharp)](https://github.com/duosecurity/duo_universal_csharp/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/duo_universal_csharp)](https://github.com/duosecurity/duo_universal_csharp/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/duo_universal_csharp/blob/master/LICENSES/BSD-3-Clause.txt)

This library allows a web developer to quickly add Duo's interactive, self-service, two-factor authentication to any .NET web login form.

See our developer documentation at https://www.duosecurity.com/docs/duoweb for guidance on integrating Duo 2FA into your web application.

What's here:
* `DuoUniversal` - The Duo SDK for interacting with the Duo Universal Prompt
* `DuoUniversal.Example` - An example web application with Duo integrated

The example application has a dedicated README with further instructions on how to build and run it.

# Usage
This library requires .NET Core 3.1 or higher, or .NET Framework 4.7.1 or higher

The library is available on NuGet at https://www.nuget.org/packages/DuoUniversal/1.3.1

Include it in your .NET project with:

`dotnet add package DuoUniversal --version 1.3.1`

## TLS 1.2 and 1.3 Support

Duo_universal_csharp uses the .NET libraries for TLS operations.  .NET 4.7 or later is required for TLS 1.2; .NET 4.8 or later is required for TLS 1.3.

## Building with the .NET CLI
Run `dotnet build` to generate the assemblies.

# Testing

The tests require .NET Core 6.0.

## With the .NET CLI
From the root directory run:

`dotnet test`

# Linting

## With the .NET CLI
Check the code format with:

`dotnet format --verify-no-changes`

# Support

Please report any bugs, feature requests, or issues to us directly at support@duosecurity.com.

Thank you for using Duo!

https://duo.com/
