# Étape de build
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /app

COPY WebSso/*.csproj ./WebSso/
RUN dotnet restore ./WebSso/WebSso.csproj

COPY WebSso/ ./WebSso/
WORKDIR /app/WebSso
RUN dotnet publish -c Release -o /app/publish

# Étape de runtime
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "WebSso.dll"]
