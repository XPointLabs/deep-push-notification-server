FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src
COPY Deep.Push.NotificationServer.slnx ./
COPY src/Deep.Push.Server/Deep.Push.Server.csproj src/Deep.Push.Server/
RUN dotnet restore src/Deep.Push.Server/Deep.Push.Server.csproj
COPY src/Deep.Push.Server/ src/Deep.Push.Server/
RUN dotnet publish src/Deep.Push.Server/Deep.Push.Server.csproj -c Release -o /app --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine
RUN apk add --no-cache curl libsodium
WORKDIR /app
COPY --from=build /app ./
USER $APP_UID
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "Deep.Push.Server.dll"]
