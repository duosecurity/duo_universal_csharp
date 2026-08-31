<img width="3136" height="1844" alt="image" src="https://github.com/user-attachments/assets/80d43794-b2e9-4655-af30-beb88ece69ae" />

<img width="1244" height="1428" alt="image" src="https://github.com/user-attachments/assets/85a3f8e3-74e4-4c60-9733-64a2847e2d4d" />
<img width="854" height="1356" alt="image" src="https://github.com/user-attachments/assets/eed3b9c3-9ea9-4cc4-92e2-6e9529f335b8" />
<img width="818" height="1216" alt="image" src="https://github.com/user-attachments/assets/15356726-a253-4bbe-a4ae-e3daebcacb3e" />
<img width="806" height="1006" alt="image" src="https://github.com/user-attachments/assets/c3fb226c-523f-4b18-96bf-33dfc212eaf1" />
<img width="776" height="1180" alt="image" src="https://github.com/user-attachments/assets/9313c7a4-5ce1-4b21-a0b9-9cc13825cd45" />
<img width="876" height="1090" alt="image" src="https://github.com/user-attachments/assets/55cc9727-a154-4dcf-9f5e-15309fcba773" />
<img width="808" height="986" alt="image" src="https://github.com/user-attachments/assets/33f740ce-ea38-4d88-a1a4-da5e293b942b" />
<img width="3104" height="1738" alt="image" src="https://github.com/user-attachments/assets/8d1a57c7-73be-4442-a366-b9b1a86716d2" />
<img width="3136" height="1844" alt="image" src="https://github.com/user-attachments/assets/041d7adc-6439-4a98-a14c-885e61713bb2" />
<img width="3136" height="4380" alt="image" src="https://github.com/user-attachments/assets/f63ac045-fbc4-4371-9136-5b2ad0bc5dce" />

Credentiale ---->

client ID : DIJAYTMEB36S4FIOXI7F
client secret : Pp9UJnNA7CQ10wlP2CLyWTHW8n9KH6Xjefa1KQJu
API hostname : api-8905b780.duosecurity.com

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

