using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Contracts.Redis;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Expressions;
using Ptlk.RedisSnmp.Services.Redis;
using Ptlk.RedisSnmp.Services.Snmp;

namespace Ptlk.RedisSnmp.Services.Browser;

public sealed record BrowserPointSnapshot(
    string Kind,
    string AgentId,
    string DisplayName,
    string SourcePath,
    string NumericOid,
    string Access,
    string? LocalValue,
    string LocalQuality,
    DateTimeOffset? LocalTimestamp,
    string? LastError,
    string? RedisKey,
    bool Owned,
    string? OwnershipStatus,
    PointStateContract? RedisState);

public sealed class BrowserSnapshotService(
    AppDbContext db,
    SnmpValueCache cache,
    ExpressionValueCache expressionCache,
    RedisPointOwnershipService ownership,
    RedisPointStateService redisState)
{
    public async Task<IReadOnlyList<BrowserPointSnapshot>> SnapshotAsync(CancellationToken cancellationToken = default)
    {
        var points = await db.SnmpPointConfigs
            .AsNoTracking()
            .Include(point => point.AgentConfig)
            .OrderBy(point => point.AgentConfig!.AgentId)
            .ThenBy(point => point.NumericOid)
            .ToListAsync(cancellationToken);
        var mappings = await db.RedisMappings.AsNoTracking().ToDictionaryAsync(m => m.SourcePath, m => m, StringComparer.OrdinalIgnoreCase, cancellationToken);
        var claims = ownership.Snapshot().ToDictionary(c => c.SourcePath, c => c, StringComparer.OrdinalIgnoreCase);

        var rowTasks = points.Select(point => BuildRowAsync(point, mappings, claims, cancellationToken));
        var rows = (await Task.WhenAll(rowTasks)).ToList();

        var expressions = await db.ExpressionConfigs
            .AsNoTracking()
            .OrderBy(expression => expression.Name)
            .ToListAsync(cancellationToken);
        foreach (var expression in expressions)
        {
            rows.Add(await BuildExpressionRowAsync(expression, mappings, cancellationToken));
        }

        return rows;
    }

    private async Task<BrowserPointSnapshot> BuildRowAsync(
        SnmpPointConfig point,
        IReadOnlyDictionary<string, RedisMapping> mappings,
        IReadOnlyDictionary<string, PointOwnershipClaimResult> claims,
        CancellationToken cancellationToken)
    {
        mappings.TryGetValue(point.SourcePath, out var mapping);
        claims.TryGetValue(point.SourcePath, out var claim);
        var local = cache.Get(point.SourcePath);
        var redis = await ReadRedisStateAsync(mapping?.RedisKey, cancellationToken);

        return new BrowserPointSnapshot(
            "SNMP",
            point.AgentConfig?.AgentId ?? "-",
            DisplayPoint(point),
            point.SourcePath,
            point.NumericOid,
            point.Access,
            local?.Value,
            local?.Quality ?? "unset",
            local?.Timestamp,
            local?.LastErrorMessage,
            mapping?.RedisKey,
            claim?.Acquired ?? !RedisPointOwnershipService.RequiresOwnership(point.SourcePath),
            claim?.Status,
            redis);
    }

    private async Task<BrowserPointSnapshot> BuildExpressionRowAsync(
        ExpressionConfig expression,
        IReadOnlyDictionary<string, RedisMapping> mappings,
        CancellationToken cancellationToken)
    {
        var sourcePath = ExpressionService.SourcePathFor(expression.Name);
        mappings.TryGetValue(sourcePath, out var mapping);
        var local = expressionCache.Get(sourcePath);
        var redis = await ReadRedisStateAsync(mapping?.RedisKey, cancellationToken);

        return new BrowserPointSnapshot(
            "Expression",
            "Expression",
            expression.Name,
            sourcePath,
            "",
            expression.Rw,
            local?.Value,
            local?.Quality ?? "unset",
            local is null ? null : DateTimeOffset.FromUnixTimeMilliseconds(local.Timestamp),
            local?.Error,
            mapping?.RedisKey,
            true,
            null,
            redis);
    }

    private static string DisplayPoint(SnmpPointConfig point) =>
        !string.IsNullOrWhiteSpace(point.MibLabel)
            ? point.MibLabel
            : point.NumericOid;

    private async Task<PointStateContract?> ReadRedisStateAsync(string? redisKey, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(redisKey))
        {
            return null;
        }

        try
        {
            return await redisState.ReadAsync(redisKey, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }
}
