using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using StackExchange.Redis;

namespace Ptlk.RedisSnmp.Services.Redis;

public sealed class RedisConnectionFactory(
    IOptions<RedisOptions> options,
    ILogger<RedisConnectionFactory> logger) : IAsyncDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private IConnectionMultiplexer? _connection;

    public async Task<IConnectionMultiplexer> GetConnectionAsync(CancellationToken cancellationToken = default)
    {
        if (_connection is { IsConnected: true })
        {
            return _connection;
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_connection is { IsConnected: true })
            {
                return _connection;
            }

            _connection?.Dispose();
            var config = CreateConfiguration(options.Value);
            logger.LogInformation(
                "Connecting Redis {Host}:{Port}, db {DatabaseIndex}",
                options.Value.Host,
                options.Value.Port,
                options.Value.DatabaseIndex);

            _connection = await ConnectionMultiplexer.ConnectAsync(config);
            return _connection;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IDatabase> GetDatabaseAsync(CancellationToken cancellationToken = default)
    {
        var connection = await GetConnectionAsync(cancellationToken);
        return connection.GetDatabase(options.Value.DatabaseIndex);
    }

    public async Task<bool> IsConnectedAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var database = await GetDatabaseAsync(cancellationToken);
            _ = await database.PingAsync();
            return true;
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Redis connectivity check failed");
            return false;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync();
        try
        {
            _connection?.Dispose();
            _connection = null;
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }

    private static ConfigurationOptions CreateConfiguration(RedisOptions redis)
    {
        var config = new ConfigurationOptions
        {
            ConnectTimeout = redis.ConnectTimeoutMs,
            SyncTimeout = redis.SyncTimeoutMs,
            AbortOnConnectFail = redis.AbortConnect,
            ConnectRetry = redis.ConnectRetry,
            KeepAlive = redis.KeepAliveSeconds,
            Ssl = redis.Ssl
        };
        config.EndPoints.Add(redis.Host, redis.Port);
        if (!string.IsNullOrWhiteSpace(redis.AclUsername))
        {
            config.User = redis.AclUsername;
        }
        if (!string.IsNullOrWhiteSpace(redis.AclPassword))
        {
            config.Password = redis.AclPassword;
        }

        return config;
    }
}
