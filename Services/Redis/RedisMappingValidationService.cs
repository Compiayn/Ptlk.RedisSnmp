using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;

namespace Ptlk.RedisSnmp.Services.Redis;

public sealed record MappingValidationResult(bool Success, string? Error);

public sealed record RedisMappingKeyCheckResult(string SourcePath, string RedisKey);

public sealed class RedisMappingValidationService(
    AppDbContext db,
    RedisConnectionFactory redis)
{
    private static readonly string[] ValidSourcePrefixes = ["snmp:", "snmp-health:", "snmp-trap:", "rds:"];
    private static readonly HashSet<string> HealthFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "reachable",
        "lastPollMs",
        "errorCount"
    };

    public Task<List<RedisMapping>> ListAsync(CancellationToken cancellationToken = default) =>
        db.RedisMappings
            .AsNoTracking()
            .OrderBy(m => m.SourcePath)
            .ToListAsync(cancellationToken);

    public MappingValidationResult Validate(string sourcePath, string redisKey)
    {
        if (string.IsNullOrWhiteSpace(sourcePath)
            || !ValidSourcePrefixes.Any(prefix => sourcePath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
        {
            return new MappingValidationResult(false, "SourcePath must start with snmp:, snmp-health:, snmp-trap:, or rds:.");
        }

        if (string.IsNullOrWhiteSpace(redisKey))
        {
            return new MappingValidationResult(false, "RedisKey is required.");
        }

        if (redisKey.StartsWith("cmd:", StringComparison.OrdinalIgnoreCase)
            || redisKey.StartsWith("evt:", StringComparison.OrdinalIgnoreCase)
            || redisKey.StartsWith("record:", StringComparison.OrdinalIgnoreCase))
        {
            return new MappingValidationResult(false, "RedisKey must not point to command, event, or record namespaces.");
        }

        if (!redisKey.StartsWith("point:", StringComparison.OrdinalIgnoreCase))
        {
            return new MappingValidationResult(false, "RedisKey must start with point:.");
        }

        return new MappingValidationResult(true, null);
    }

    public async Task<MappingValidationResult> ValidateAsync(
        string sourcePath,
        string redisKey,
        int? editId = null,
        CancellationToken cancellationToken = default)
    {
        var result = Validate(sourcePath, redisKey);
        if (!result.Success)
        {
            return result;
        }

        var normalizedSource = sourcePath.Trim();
        var normalizedKey = redisKey.Trim();
        var effectiveEditId = editId ?? 0;

        if (await db.RedisMappings.AnyAsync(m => m.SourcePath == normalizedSource && m.Id != effectiveEditId, cancellationToken))
        {
            return new MappingValidationResult(false, $"SourcePath '{normalizedSource}' is already used by another mapping.");
        }

        if (await db.RedisMappings.AnyAsync(m => m.RedisKey == normalizedKey && m.Id != effectiveEditId, cancellationToken))
        {
            return new MappingValidationResult(false, $"RedisKey '{normalizedKey}' is already used by another mapping.");
        }

        if (normalizedSource.StartsWith("snmp:", StringComparison.OrdinalIgnoreCase)
            && !await db.SnmpPointConfigs.AnyAsync(p => p.SourcePath == normalizedSource, cancellationToken))
        {
            return new MappingValidationResult(false, $"SourcePath '{normalizedSource}' does not match any SNMP point.");
        }

        if (normalizedSource.StartsWith("snmp-health:", StringComparison.OrdinalIgnoreCase)
            && !IsValidHealthSource(normalizedSource))
        {
            return new MappingValidationResult(false, $"SourcePath '{normalizedSource}' does not use a supported SNMP health field.");
        }

        if (normalizedSource.StartsWith("snmp-trap:", StringComparison.OrdinalIgnoreCase)
            && !await HasTrapReferenceAsync(normalizedSource, cancellationToken))
        {
            return new MappingValidationResult(false, $"SourcePath '{normalizedSource}' does not match a trap rule.");
        }

        return new MappingValidationResult(true, null);
    }

    public async Task<RedisMapping> CreateOrUpdateAsync(
        int? id,
        string sourcePath,
        string redisKey,
        CancellationToken cancellationToken = default)
    {
        var result = await ValidateAsync(sourcePath, redisKey, id, cancellationToken);
        if (!result.Success)
        {
            throw new InvalidOperationException(result.Error);
        }

        var normalizedSource = sourcePath.Trim();
        var normalizedKey = redisKey.Trim();

        var mapping = id is > 0
            ? await db.RedisMappings.FirstAsync(m => m.Id == id.Value, cancellationToken)
            : new RedisMapping();

        mapping.SourcePath = normalizedSource;
        mapping.RedisKey = normalizedKey;

        if (id is null or <= 0)
        {
            db.RedisMappings.Add(mapping);
        }

        await db.SaveChangesAsync(cancellationToken);
        return mapping;
    }

    public async Task DeleteAsync(int id, CancellationToken cancellationToken = default)
    {
        var mapping = await db.RedisMappings.FindAsync([id], cancellationToken);
        if (mapping is null)
        {
            return;
        }

        db.RedisMappings.Remove(mapping);
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<RedisMappingKeyCheckResult>> VerifyExistingRedisKeysAsync(CancellationToken cancellationToken = default)
    {
        var mappings = await db.RedisMappings.AsNoTracking().ToListAsync(cancellationToken);
        if (mappings.Count == 0)
        {
            return [];
        }

        var database = await redis.GetDatabaseAsync(cancellationToken);
        var missing = new List<RedisMappingKeyCheckResult>();
        foreach (var mapping in mappings)
        {
            if (!await database.KeyExistsAsync(mapping.RedisKey))
            {
                missing.Add(new RedisMappingKeyCheckResult(mapping.SourcePath, mapping.RedisKey));
            }
        }

        return missing;
    }

    private static bool IsValidHealthSource(string sourcePath)
    {
        var parts = sourcePath.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts.Length == 2
               && parts[0].Length > "snmp-health:".Length
               && HealthFields.Contains(parts[1]);
    }

    private async Task<bool> HasTrapReferenceAsync(string sourcePath, CancellationToken cancellationToken)
    {
        var payload = sourcePath["snmp-trap:".Length..];
        var parts = payload.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2)
        {
            return false;
        }

        var agentId = parts[0];
        var trapOid = parts[1];
        return await db.SnmpTrapRuleConfigs.AnyAsync(
            rule => rule.AgentId == agentId && rule.TrapOid == trapOid,
            cancellationToken);
    }
}
