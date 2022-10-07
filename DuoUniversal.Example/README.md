# Duo Universal Prompt C# Sample Application

This example application demonstrates how to integrate the Duo Universal C# client into a simple ASP.NET web application.

### Caveats

The Duo Universal C# client provides asynchronous methods and that is the paradigm demonstrated in the example.  If you need to use the C# client from a synchronous web application, you will need to wrap the async calls in synchronizing code.

A detailed investigation into possible approaches can be found on [MSDN](https://docs.microsoft.com/en-us/archive/msdn-magazine/2015/july/async-programming-brownfield-async-development#transform-synchronous-to-asynchronous-code).

Users of this repository have reported that the following approach works in their ASP.NET web app:

`var token = Task.Run(async () => { return await duoClient.ExchangeAuthorizationCodeFor2faResult(context.Request["code"], username); }).Result;`

Duo has used the following approach in internal products:

`var _idToken = duoClient.ExchangeAuthorizationCodeFor2faResult(duoCode, username).GetAwaiter().GetResult();`

## Build

### With the .NET CLI
From the DuoUniversal.Example directory run:

`dotnet build`

## Run

In order to run this project, ensure the values in `DuoUniversal.Example/appsettings.json` (or `appsettings.Development.json` if you prefer) 
are filled out with the values from the Duo Admin Panel (Client Id, Client Secret, API Host).

### With the .NET CLI
From the DuoUniversal.Example base directory run the following to start the server:

`dotnet run --framework net6.0`

Or you can use `--framework netcoreapp3.1` if you prefer.

## Interact

Navigate to <https://localhost:5001> or <http://localhost:5000> to see a mock user login form.  Enter a Duo username and any password to initiate Duo 2FA.

