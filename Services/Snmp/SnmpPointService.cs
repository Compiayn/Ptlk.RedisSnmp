using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Paths;

namespace Ptlk.RedisSnmp.Services.Snmp;

public sealed class SnmpPointService(
    AppDbContext db,
    SnmpSourcePathService paths)
{
    public Task<List<SnmpPointConfig>> ListAsync(CancellationToken cancellationToken = default) =>
        db.SnmpPointConfigs
            .AsNoTracking()
            .Include(p => p.AgentConfig)
            .OrderBy(p => p.AgentConfig!.AgentId)
            .ThenBy(p => p.NumericOid)
            .ToListAsync(cancellationToken);

    public async Task<SnmpPointConfig> CreateOrUpdateAsync(
        SnmpPointConfig input,
        CancellationToken cancellationToken = default) =>
        await SaveAsync(input, overwriteExisting: false, cancellationToken);

    public async Task<SnmpPointConfig> CreateOrOverwriteAsync(
        SnmpPointConfig input,
        CancellationToken cancellationToken = default)
    {
        var saved = await CreateOrOverwriteBatchAsync([input], cancellationToken);
        return saved[0];
    }

    public async Task<IReadOnlyList<SnmpPointConfig>> CreateOrOverwriteBatchAsync(
        IReadOnlyCollection<SnmpPointConfig> inputs,
        CancellationToken cancellationToken = default)
    {
        if (inputs.Count == 0)
        {
            return [];
        }

        var batch = inputs.ToList();
        foreach (var input in batch)
        {
            Validate(input);
        }

        var agentIds = batch.Select(input => input.AgentConfigId).Distinct().ToList();
        var agents = await db.SnmpAgentConfigs
            .Where(agent => agentIds.Contains(agent.Id))
            .ToDictionaryAsync(agent => agent.Id, cancellationToken);
        if (agents.Count != agentIds.Count)
        {
            throw new InvalidOperationException("One or more selected points reference an unavailable agent.");
        }

        var prepared = batch.Select(input =>
        {
            var agent = agents[input.AgentConfigId];
            var numericOid = paths.NormalizeNumericOid(input.NumericOid);
            return new PreparedPoint(input, agent, numericOid, paths.BuildPointSourcePath(agent.AgentId, numericOid));
        }).ToList();

        var duplicateSourcePath = prepared
            .GroupBy(item => item.SourcePath, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(group => group.Count() > 1)?.Key;
        if (duplicateSourcePath is not null)
        {
            throw new InvalidOperationException($"Selected points contain duplicate source path '{duplicateSourcePath}'.");
        }

        var existingPoints = await db.SnmpPointConfigs
            .Where(point => agentIds.Contains(point.AgentConfigId))
            .ToListAsync(cancellationToken);
        var existingBySourcePath = existingPoints.ToDictionary(point => point.SourcePath, StringComparer.OrdinalIgnoreCase);
        var saved = new List<SnmpPointConfig>(prepared.Count);

        foreach (var item in prepared)
        {
            var isNew = !existingBySourcePath.TryGetValue(item.SourcePath, out var entity);
            entity ??= new SnmpPointConfig();
            Apply(entity, item.Input, item.Agent, item.NumericOid, item.SourcePath);
            if (isNew)
            {
                db.SnmpPointConfigs.Add(entity);
            }

            saved.Add(entity);
        }

        await db.SaveChangesAsync(cancellationToken);
        return saved;
    }

    private async Task<SnmpPointConfig> SaveAsync(
        SnmpPointConfig input,
        bool overwriteExisting,
        CancellationToken cancellationToken)
    {
        Validate(input);
        var agent = await db.SnmpAgentConfigs.FirstAsync(a => a.Id == input.AgentConfigId, cancellationToken);
        var numericOid = paths.NormalizeNumericOid(input.NumericOid);
        var sourcePath = paths.BuildPointSourcePath(agent.AgentId, numericOid);

        SnmpPointConfig? entity = null;
        if (input.Id > 0)
        {
            entity = await db.SnmpPointConfigs.FirstAsync(p => p.Id == input.Id, cancellationToken);
        }
        else if (overwriteExisting)
        {
            entity = await db.SnmpPointConfigs.FirstOrDefaultAsync(p => p.SourcePath == sourcePath, cancellationToken);
        }

        var isNew = entity is null;
        entity ??= new SnmpPointConfig();

        Apply(entity, input, agent, numericOid, sourcePath);

        if (isNew)
        {
            db.SnmpPointConfigs.Add(entity);
        }

        await db.SaveChangesAsync(cancellationToken);
        return entity;
    }

    private static void Apply(
        SnmpPointConfig entity,
        SnmpPointConfig input,
        SnmpAgentConfig agent,
        string numericOid,
        string sourcePath)
    {
        entity.AgentConfigId = agent.Id;
        entity.NumericOid = numericOid;
        entity.SourcePath = sourcePath;
        entity.ValueType = input.ValueType.Trim();
        entity.Access = input.Access.Trim();
        entity.Description = NullIfWhiteSpace(input.Description);
        entity.MibLabel = NullIfWhiteSpace(input.MibLabel);
        entity.MibModule = NullIfWhiteSpace(input.MibModule);
        entity.MibSyntax = NullIfWhiteSpace(input.MibSyntax);
        entity.MibAccess = NullIfWhiteSpace(input.MibAccess);
        entity.MibDescription = NullIfWhiteSpace(input.MibDescription);
    }

    public async Task DeleteAsync(int id, CancellationToken cancellationToken = default)
    {
        var entity = await db.SnmpPointConfigs.FindAsync([id], cancellationToken);
        if (entity is null)
        {
            return;
        }

        db.SnmpPointConfigs.Remove(entity);
        await db.SaveChangesAsync(cancellationToken);
    }

    private void Validate(SnmpPointConfig point)
    {
        if (point.AgentConfigId <= 0)
        {
            throw new InvalidOperationException("Agent is required.");
        }
        _ = paths.NormalizeNumericOid(point.NumericOid);

        if (point.ValueType is not SnmpValueTypes.String
            and not SnmpValueTypes.Integer
            and not SnmpValueTypes.Double
            and not SnmpValueTypes.Boolean
            and not SnmpValueTypes.Timeticks
            and not SnmpValueTypes.Oid)
        {
            throw new InvalidOperationException("ValueType is invalid.");
        }

        if (point.Access is not SnmpAccessModes.ReadOnly
            and not SnmpAccessModes.ReadWrite
            and not SnmpAccessModes.WriteOnly)
        {
            throw new InvalidOperationException("Access is invalid.");
        }

    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private sealed record PreparedPoint(
        SnmpPointConfig Input,
        SnmpAgentConfig Agent,
        string NumericOid,
        string SourcePath);
}
