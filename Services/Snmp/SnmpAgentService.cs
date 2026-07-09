using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Paths;

namespace Ptlk.RedisSnmp.Services.Snmp;

public sealed class SnmpAgentService(
    AppDbContext db,
    SnmpSourcePathService paths,
    IOptions<SnmpRuntimeOptions> runtimeOptions)
{
    public Task<List<SnmpAgentConfig>> ListAsync(CancellationToken cancellationToken = default) =>
        db.SnmpAgentConfigs
            .AsNoTracking()
            .Include(a => a.CredentialConfig)
            .Include(a => a.TrapCredentialConfig)
            .Include(a => a.PreferredMibSet)
            .Include(a => a.Points)
            .OrderBy(a => a.AgentId)
            .ToListAsync(cancellationToken);

    public async Task<SnmpAgentConfig> CreateOrUpdateAsync(
        SnmpAgentConfig input,
        CancellationToken cancellationToken = default)
    {
        Validate(input);
        var entity = input.Id > 0
            ? await db.SnmpAgentConfigs.FirstAsync(a => a.Id == input.Id, cancellationToken)
            : new SnmpAgentConfig();

        entity.AgentId = input.AgentId.Trim();
        entity.DisplayName = input.DisplayName.Trim();
        entity.Host = input.Host.Trim();
        entity.Port = input.Port;
        entity.SnmpVersion = input.SnmpVersion.Trim();
        entity.CredentialConfigId = input.CredentialConfigId;
        entity.TrapCredentialConfigId = input.TrapCredentialConfigId;
        entity.PreferredMibSetId = input.PreferredMibSetId;
        entity.TimeoutMs = input.TimeoutMs > 0 ? input.TimeoutMs : runtimeOptions.Value.DefaultTimeoutMs;
        entity.RetryCount = input.RetryCount >= 0 ? input.RetryCount : runtimeOptions.Value.DefaultRetryCount;
        entity.PollingRateMs = input.PollingRateMs > 0 ? input.PollingRateMs : runtimeOptions.Value.DefaultPollingRateMs;
        entity.Enabled = input.Enabled;
        entity.Description = NullIfWhiteSpace(input.Description);

        if (input.Id <= 0)
        {
            db.SnmpAgentConfigs.Add(entity);
        }

        await db.SaveChangesAsync(cancellationToken);
        return entity;
    }

    public async Task DeleteAsync(int id, CancellationToken cancellationToken = default)
    {
        var entity = await db.SnmpAgentConfigs.FindAsync([id], cancellationToken);
        if (entity is null)
        {
            return;
        }

        db.SnmpAgentConfigs.Remove(entity);
        await db.SaveChangesAsync(cancellationToken);
    }

    private void Validate(SnmpAgentConfig agent)
    {
        if (!paths.IsSafeAgentId(agent.AgentId))
        {
            throw new InvalidOperationException("AgentId must be non-empty and must not contain ':', '*', '/', '\\', or whitespace.");
        }
        if (string.IsNullOrWhiteSpace(agent.DisplayName))
        {
            throw new InvalidOperationException("DisplayName is required.");
        }
        if (string.IsNullOrWhiteSpace(agent.Host))
        {
            throw new InvalidOperationException("Host is required.");
        }
        if (agent.Port is <= 0 or > 65535)
        {
            throw new InvalidOperationException("Port is invalid.");
        }
        if (agent.SnmpVersion is not SnmpVersions.V1 and not SnmpVersions.V2C and not SnmpVersions.V3)
        {
            throw new InvalidOperationException("SNMP version must be v1, v2c, or v3.");
        }
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
