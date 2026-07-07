using System.Globalization;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Redis;
using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Startup;
using StackExchange.Redis;

namespace Ptlk.RedisSnmp.Services.Redis;

public sealed class RedisPointUpdateException(
    string status,
    string redisKey,
    string message,
    Exception? innerException = null) : InvalidOperationException(message, innerException)
{
    public string Status { get; } = status;
    public string RedisKey { get; } = redisKey;
}

public sealed class RedisPointStateService(
    RedisConnectionFactory redis,
    RedisPubSubService pubSub,
    IOptions<RedisSnmpOptions> redisSnmpOptions,
    RuntimeModeService runtime)
{
    private const string UpdateDynamicFieldsScript = """
        if redis.call('EXISTS', KEYS[1]) == 0 then
            return {'missing'}
        end

        local pointType = redis.call('HGET', KEYS[1], 'type')
        local access = redis.call('HGET', KEYS[1], 'access')
        local currentVersionValue = redis.call('HGET', KEYS[1], 'version')
        if not pointType or pointType == '' or not access or access == '' then
            return {'metadata_missing'}
        end

        if not currentVersionValue or currentVersionValue == '' then
            return {'version_missing'}
        end

        local currentVersion = tonumber(currentVersionValue)
        if not currentVersion then
            return {'version_invalid'}
        end

        local nextVersion = currentVersion + 1

        if ARGV[1] == '1' then
            redis.call('HSET', KEYS[1], 'value', ARGV[2])
        else
            redis.call('HDEL', KEYS[1], 'value')
        end

        redis.call('HSET', KEYS[1],
            'quality', ARGV[3],
            'timestamp', ARGV[4],
            'version', tostring(nextVersion),
            'source', ARGV[5])

        return {'ok', tostring(nextVersion), pointType, access, redis.call('HGET', KEYS[1], 'unit') or ''}
        """;

    public async Task<PointStateContract?> ReadAsync(string key, CancellationToken cancellationToken = default)
    {
        var database = await redis.GetDatabaseAsync(cancellationToken);
        if (!await database.KeyExistsAsync(key))
        {
            return null;
        }

        var values = await database.HashGetAllAsync(key);
        var map = values.ToDictionary(x => x.Name.ToString(), x => x.Value.ToString(), StringComparer.OrdinalIgnoreCase);

        return new PointStateContract(
            key,
            map.GetValueOrDefault("value"),
            map.GetValueOrDefault("quality") ?? SnmpQuality.Unset,
            map.GetValueOrDefault("type"),
            ParseLong(map.GetValueOrDefault("timestamp")),
            ParseLong(map.GetValueOrDefault("version")),
            map.GetValueOrDefault("source") ?? "",
            map.GetValueOrDefault("access"),
            map.GetValueOrDefault("unit"));
    }

    public async Task<PointStateContract> UpdateDynamicFieldsAsync(
        RedisMapping mapping,
        string? value,
        string quality,
        string source,
        CancellationToken cancellationToken = default)
    {
        var key = mapping.RedisKey;
        try
        {
            var database = await redis.GetDatabaseAsync(cancellationToken);
            if (!await database.KeyExistsAsync(key))
            {
                throw CreateUpdateException(mapping, "missing_key", $"Redis point key '{key}' does not exist.");
            }

            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var valueArgument = value is null ? string.Empty : value;
            var result = (RedisResult[]?)await database.ScriptEvaluateAsync(
                UpdateDynamicFieldsScript,
                [key],
                [
                    value is null ? "0" : "1",
                    valueArgument,
                    quality,
                    now.ToString(CultureInfo.InvariantCulture),
                    source
                ]);

            var status = result is { Length: > 0 } ? result[0].ToString() : "";
            if (status == "missing")
            {
                throw CreateUpdateException(mapping, "missing_key", $"Redis point key '{key}' does not exist.");
            }

            if (status == "metadata_missing")
            {
                throw CreateUpdateException(mapping, "metadata_missing", $"Redis point key '{key}' is missing Asset-owned metadata.");
            }

            if (status == "version_missing")
            {
                throw CreateUpdateException(mapping, "version_missing", $"Redis point key '{key}' is missing required field 'version'.");
            }

            if (status == "version_invalid")
            {
                throw CreateUpdateException(mapping, "version_invalid", $"Redis point key '{key}' has an invalid required field 'version'.");
            }

            if (status != "ok" || result is not { Length: >= 5 } || !long.TryParse(result[1].ToString(), out var version))
            {
                throw CreateUpdateException(mapping, "unexpected_result", $"Redis point key '{key}' dynamic update returned an unexpected result.");
            }

            var updated = new PointStateContract(
                key,
                value,
                quality,
                result[2].ToString(),
                now,
                version,
                source,
                result[3].ToString(),
                result[4].ToString());

            await PublishValueUpdatedAsync(updated, cancellationToken);
            runtime.ClearRedisOutputDiagnosticsForMapping(mapping.SourcePath, mapping.RedisKey);
            return updated;
        }
        catch (RedisPointUpdateException)
        {
            throw;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw CreateUpdateException(
                mapping,
                "redis_output_failed",
                $"Redis point key '{key}' dynamic update failed: {ex.Message}",
                ex);
        }
    }

    private async Task PublishValueUpdatedAsync(
        PointStateContract point,
        CancellationToken cancellationToken)
    {
        var options = redisSnmpOptions.Value;
        var evt = new ValueUpdatedEventContract(
            Schema: 1,
            Type: "value.updated",
            MessageId: Guid.NewGuid().ToString("N"),
            Key: point.Key,
            Value: point.Value,
            Quality: point.Quality,
            Version: point.Version,
            Timestamp: point.Timestamp,
            Source: options.SourceName);

        await pubSub.PublishAsync("evt:value-updated", evt, cancellationToken);
    }

    private static long ParseLong(string? value) =>
        long.TryParse(value, out var parsed) ? parsed : 0;

    private RedisPointUpdateException CreateUpdateException(
        RedisMapping mapping,
        string status,
        string message,
        Exception? innerException = null)
    {
        runtime.ReportRedisOutputDiagnostic(
            "redis_writer",
            mapping.SourcePath,
            mapping.RedisKey,
            status,
            message);
        return new RedisPointUpdateException(status, mapping.RedisKey, message, innerException);
    }
}
