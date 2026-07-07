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
            .ThenBy(p => p.PointName)
            .ToListAsync(cancellationToken);

    public async Task<SnmpPointConfig> CreateOrUpdateAsync(
        SnmpPointConfig input,
        CancellationToken cancellationToken = default)
    {
        Validate(input);
        var agent = await db.SnmpAgentConfigs.FirstAsync(a => a.Id == input.AgentConfigId, cancellationToken);
        var numericOid = paths.NormalizeNumericOid(input.NumericOid);
        var sourcePath = paths.BuildPointSourcePath(agent.AgentId, numericOid);

        var entity = input.Id > 0
            ? await db.SnmpPointConfigs.FirstAsync(p => p.Id == input.Id, cancellationToken)
            : new SnmpPointConfig();

        entity.AgentConfigId = agent.Id;
        entity.PointName = input.PointName.Trim();
        entity.NumericOid = numericOid;
        entity.SourcePath = sourcePath;
        entity.ValueType = input.ValueType.Trim();
        entity.PollEnabled = input.PollEnabled;
        entity.SetEnabled = input.SetEnabled;
        entity.Access = input.Access.Trim();
        entity.Description = NullIfWhiteSpace(input.Description);
        entity.MibLabel = NullIfWhiteSpace(input.MibLabel);

        if (input.Id <= 0)
        {
            db.SnmpPointConfigs.Add(entity);
        }

        await db.SaveChangesAsync(cancellationToken);
        return entity;
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
        if (string.IsNullOrWhiteSpace(point.PointName))
        {
            throw new InvalidOperationException("PointName is required.");
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

        if (point.SetEnabled && point.Access == SnmpAccessModes.ReadOnly)
        {
            throw new InvalidOperationException("Read-only points cannot enable SNMP Set.");
        }
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
