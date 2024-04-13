FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build-env
WORKDIR /App
EXPOSE 80

ENV ASPNETCORE_URLS=http://+:8080

# Copy everything
COPY . ./
# Restore as distinct layers
RUN dotnet restore UserControl.Api.Authenticacao.csproj
# Build and publish a release
RUN dotnet publish -c Release -o out UserControl.Api.Authenticacao.csproj

# Build runtime image
FROM mcr.microsoft.com/dotnet/aspnet:7.0
WORKDIR /App
COPY --from=build-env /App/out .
ENTRYPOINT ["dotnet", "UserControl.Api.Authenticacao.dll"]