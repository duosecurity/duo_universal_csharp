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

# Usage
This library requires .NET Core 3.1 or higher, or .NET Framework 4.7.1 or higher

The library is available on NuGet at https://www.nuget.org/packages/DuoUniversal/1.1.3

Include it in your .NET project with:

`dotnet add package DuoUniversal --version 1.1.3`

## With the .NET CLI
Run `dotnet build` to generate the assemblies.

# Demo

## Build

### With the .NET CLI
From the DuoUniversal.Example directory run:

`dotnet build`

## Run

In order to run this project, ensure the values in `DuoUniversal.Example/appsettings.json` (or `appsettings.Development.json` if you prefer) 
are filled out with the values from the Duo Admin Panel (Client Id, Client Secret, API Host, and Redirect Uri)

### With the .NET CLI
From the DuoUniversal.Example base directory run the following to start the server:

`dotnet run --framework net6.0`

Or you can use `--framework netcoreapp3.1` if you prefer.

Navigate to <https://localhost:5001> or <http://localhost:5000> to see a mock user login form.  Enter a Duo username and any password to initiate Duo 2FA.

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
