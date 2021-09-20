# Duo Universal Prompt C# Client

This library allows a web developer to quickly add Duo's interactive, self-service, two-factor authentication to any .NET web login form.

See our developer documentation at http://www.duosecurity.com/docs/duoweb for guidance on integrating Duo 2FA into your web application.

What's here:
* `DuoUniversal` - The Duo SDK for interacting with the Duo Universal Prompt
* `DuoUniversal.Example` - An example web application with Duo integrated

# Usage
This library requires (TODO determine minimum .NET versions)

Using the .NET CLI:
Run `dotnet build` to generate the assembly.

(TODO NuGet instructions)

# Demo

## Build

Using the .NET CLI:
From the DuoUniversal.Example directory run:
`dotnet build`

## Run

In order to run this project, ensure the values in `DuoUniversal.Example/appsettings.json` (or `appsettings.Development.json if you prefer`) 
are filled out with the values from the Duo Admin Panel (Client Id, Client Secret, API Host, and Redirect Uri)

Using the .NET CLI:
From the DuoUniversal.Example base directory run the following to start the server:
`dotnet run`

Navigate to <https://localhost:5001> or <http://localhost:5000> to see a mock user login form.  Enter a Duo username and any password to initiate Duo 2FA.

# Testing

Using the .NET CLI:
From the root directory run:

`dotnet test`

# Support

Please report any bugs, feature requests, or issues to us directly at support@duosecurity.com.

Thank you for using Duo!

http://www.duosecurity.com/
