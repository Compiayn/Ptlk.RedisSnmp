using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Contracts.Redis;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Services.Redis;
using Ptlk.RedisSnmp.Services.Snmp;

namespace Ptlk.RedisSnmp.Services.Browser;

public sealed record BrowserPointSnapshot(
    string AgentId,
    string PointName,
    string SourcePath,
    string NumericOid,
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
    RedisPointOwnershipService ownership,
    RedisPointStateService redisState)
{
    public async Task<IReadOnlyList<BrowserPointSnapshot>> SnapshotAsync(CancellationToken cancellationToken = default)
    {
        var points = await db.SnmpPointConfigs
            .AsNoTracking()
            .Include(point => point.AgentConfig)
            .OrderBy(point => point.AgentConfig!.AgentId)
            .ThenBy(point => point.PointName)
            .ToListAsync(cancellationToken);
        var mappings = await db.RedisMappings.AsNoTracking().ToDictionaryAsync(m => m.SourcePath, m => m, StringComparer.OrdinalIgnoreCase, cancellationToken);
        var claims = ownership.Snapshot().ToDictionary(c => c.SourcePath, c => c, StringComparer.OrdinalIgnoreCase);
        var rows = new List<BrowserPointSnapshot>();

        foreach (var point in points)
        {
            mappings.TryGetValue(point.SourcePath, out var mapping);
            claims.TryGetValue(point.SourcePath, out var claim);
            var local = cache.Get(point.SourcePath);
            PointStateContract? redis = null;
            if (mapping is not null)
            {
                try
                {
                    redis = await redisState.ReadAsync(mapping.RedisKey, cancellationToken);
                }
                catch
                {
                }
            }

            rows.Add(new BrowserPointSnapshot(
                point.AgentConfig?.AgentId ?? "-",
                point.PointName,
                point.SourcePath,
                point.NumericOid,
                local?.Value,
                local?.Quality ?? "unset",
                local?.Timestamp,
                local?.LastErrorMessage,
                mapping?.RedisKey,
                claim?.Acquired ?? !RedisPointOwnershipService.RequiresOwnership(point.SourcePath),
                claim?.Status,
                redis));
        }

        return rows;
    }
}
