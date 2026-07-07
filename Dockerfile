FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends snmp snmptrapd \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data /data/mibs /data/snmp /data/traps

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["Ptlk.RedisSnmp.csproj", "."]
RUN dotnet restore
COPY . .
RUN dotnet publish -c Release -o /app/publish --no-restore

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish /app
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
EXPOSE 10162/udp
VOLUME ["/data"]
ENTRYPOINT ["dotnet", "/app/Ptlk.RedisSnmp.dll"]
