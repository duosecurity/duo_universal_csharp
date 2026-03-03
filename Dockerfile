# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy solution and projects for restore
COPY ["duo_universal_csharp.sln", "./"]
COPY ["DuoUniversal/DuoUniversal.csproj", "DuoUniversal/"]
COPY ["DuoUniversal.Example/DuoUniversal.Example.csproj", "DuoUniversal.Example/"]
COPY ["DuoUniversal.Tests/DuoUniversal.Tests.csproj", "DuoUniversal.Tests/"]

RUN dotnet restore

# Copy everything else
COPY . .

# Build and publish
WORKDIR "/src/DuoUniversal.Example"
RUN dotnet build "DuoUniversal.Example.csproj" -c Release -o /app/build
RUN dotnet publish "DuoUniversal.Example.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Final stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "DuoUniversal.Example.dll"]
