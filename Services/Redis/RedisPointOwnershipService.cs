using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Services.Logs;
using Ptlk.RedisSnmp.Services.Startup;

namespace Ptlk.RedisSnmp.Services.Redis;

public sealed record PointOwnershipClaimResult(
    string SourcePath,
    string RedisKey,
    bool Acquired,
    string Status,
    string? Owner);

public sealed class RedisPointOwnershipService(
    RedisConnectionFactory redis,
    IOptions<RedisSnmpOptions> options,
    RuntimeModeService runtime,
    ILogger<RedisPointOwnershipService> logger)
{
    private static readonly TimeSpan ClaimRetryInterval = TimeSpan.FromSeconds(5);

    private const string ClaimScript = """
        if redis.call('EXISTS', KEYS[1]) == 0 then
            return {'missing'}
        end

        local currentOwner = redis.call('HGET', KEYS[1], 'owner')
        if not currentOwner or currentOwner == '' or currentOwner == ARGV[1] then
            redis.call('HSET', KEYS[1],
                'owner', ARGV[1],
                'owner_source', ARGV[2],
                'owner_acquired_at', ARGV[3])
            return {'ok', ARGV[1]}
        end

        return {'owned_by_other', currentOwner}
        """;

    private readonly ConcurrentDictionary<string, PointOwnershipClaimResult> _claims = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastClaimAttempts = new(StringComparer.OrdinalIgnoreCase);

    public bool IsOwned(string sourcePath)
    {
        if (!RequiresOwnership(sourcePath))
        {
            return true;
        }

        return _claims.TryGetValue(sourcePath, out var claim) && claim.Acquired;
    }

    public async Task<bool> EnsureOwnedAsync(
        string sourcePath,
        string redisKey,
        CancellationToken cancellationToken = default)
    {
        if (!RequiresOwnership(sourcePath))
        {
            return true;
        }

        if (_claims.TryGetValue(sourcePath, out var claim) && claim.Acquired)
        {
            return true;
        }

        var now = DateTimeOffset.UtcNow;
        if (_lastClaimAttempts.TryGetValue(sourcePath, out var lastAttempt)
            && now - lastAttempt < ClaimRetryInterval)
        {
            return false;
        }

        _lastClaimAttempts[sourcePath] = now;
        claim = await ClaimAsync(sourcePath, redisKey, cancellationToken);
        return claim.Acquired;
    }

    public IReadOnlyCollection<PointOwnershipClaimResult> Snapshot() =>
        _claims.Values.OrderBy(x => x.SourcePath).ToList();

    public async Task<PointOwnershipClaimResult> ClaimAsync(
        string sourcePath,
        string redisKey,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var database = await redis.GetDatabaseAsync(cancellationToken);
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture);
            var result = (StackExchange.Redis.RedisResult[]?)await database.ScriptEvaluateAsync(
                ClaimScript,
                [redisKey],
                [options.Value.ConverterId, options.Value.SourceName, now]);

            var status = result is { Length: > 0 } ? result[0].ToString() ?? "" : "";
            var owner = result is { Length: > 1 } ? result[1].ToString() : null;
            var claim = new PointOwnershipClaimResult(
                sourcePath,
                redisKey,
                status == "ok",
                string.IsNullOrWhiteSpace(status) ? "unexpected_result" : status,
                owner);

            _claims[sourcePath] = claim;
            if (claim.Acquired)
            {
                runtime.ClearRedisOutputDiagnosticsForMapping(sourcePath, redisKey);
            }
            else
            {
                ReportClaimDiagnostic(claim);
                logger.LogWarning(
                    "RedisSnmp ownership was not acquired for {SourcePath} -> {RedisKey}; status={Status}; owner={Owner}.",
                    sourcePath,
                    redisKey,
                    claim.Status,
                    claim.Owner);
            }

            return claim;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            var claim = new PointOwnershipClaimResult(
                sourcePath,
                redisKey,
                Acquired: false,
                "ownership_check_failed",
                Owner: null);
            _claims[sourcePath] = claim;
            runtime.ReportRedisOutputDiagnostic(
                "ownership",
                sourcePath,
                redisKey,
                claim.Status,
                $"Ownership check failed for {sourcePath} -> {redisKey}: {ex.Message}");
            logger.LogWarning(ex, "RedisSnmp ownership check failed for {SourcePath} -> {RedisKey}.", sourcePath, redisKey);
            return claim;
        }
    }

    public static bool RequiresOwnership(string sourcePath) =>
        sourcePath.StartsWith("snmp:", StringComparison.OrdinalIgnoreCase)
        || sourcePath.StartsWith("snmp-health:", StringComparison.OrdinalIgnoreCase)
        || sourcePath.StartsWith("snmp-trap:", StringComparison.OrdinalIgnoreCase);

    private void ReportClaimDiagnostic(PointOwnershipClaimResult claim)
    {
        var message = claim.Status switch
        {
            "missing" => $"Redis point key '{claim.RedisKey}' does not exist.",
            "owned_by_other" => $"Redis point key '{claim.RedisKey}' is owned by {claim.Owner ?? "another converter"}.",
            _ => $"Ownership was not acquired for {claim.SourcePath} -> {claim.RedisKey}; status={claim.Status}."
        };
        var status = claim.Status == "missing" ? "missing_key" : claim.Status;
        runtime.ReportRedisOutputDiagnostic(
            "ownership",
            claim.SourcePath,
            claim.RedisKey,
            status,
            message);
    }
}

public sealed class RedisPointOwnershipHostedService(
    IServiceScopeFactory scopeFactory,
    RedisPointOwnershipService ownership,
    RuntimeModeService runtime,
    ILogger<RedisPointOwnershipHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested
                   && (!runtime.Current.RedisConnected || !runtime.Current.AssetInitialized))
            {
                await Task.Delay(500, stoppingToken);
            }

            using var scope = scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var log = scope.ServiceProvider.GetRequiredService<LogService>();
            var mappings = await db.RedisMappings
                .AsNoTracking()
                .Where(m => m.SourcePath.StartsWith("snmp:")
                            || m.SourcePath.StartsWith("snmp-health:")
                            || m.SourcePath.StartsWith("snmp-trap:"))
                .OrderBy(m => m.SourcePath)
                .ToListAsync(stoppingToken);

            foreach (var mapping in mappings)
            {
                var claim = await ownership.ClaimAsync(mapping.SourcePath, mapping.RedisKey, stoppingToken);
                if (!claim.Acquired)
                {
                    await log.AddSystemAsync(
                        "Ownership",
                        "Warning",
                        $"Ownership not acquired for {claim.SourcePath} -> {claim.RedisKey}; status={claim.Status}; owner={claim.Owner ?? "-"}",
                        null,
                        stoppingToken);
                }
            }

            await log.AddSystemAsync(
                "Ownership",
                "Info",
                $"Ownership claim completed for {mappings.Count} SNMP mapping(s).",
                null,
                stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "RedisSnmp ownership claim failed.");
        }
    }
}
