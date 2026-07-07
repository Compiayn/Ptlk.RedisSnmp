using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Contracts.Trap;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Mib;
using Ptlk.RedisSnmp.Services.Redis;

namespace Ptlk.RedisSnmp.Services.Trap;

public sealed class TrapEventPublisher(
    AppDbContext db,
    MibLookupService mibLookup,
    RedisPubSubService pubSub)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<SnmpTrapMessage> PublishAsync(
        SnmpTrapMessage message,
        CancellationToken cancellationToken = default)
    {
        var agentId = message.AgentId;
        int? mibSetId = null;
        if (agentId == "unknown")
        {
            var context = await ResolveAgentContextBySourceAsync(message.SourceAddress, cancellationToken);
            agentId = context.AgentId ?? "unknown";
            mibSetId = context.PreferredMibSetId;
        }
        else
        {
            mibSetId = await db.SnmpAgentConfigs.AsNoTracking()
                .Where(a => a.AgentId == agentId)
                .Select(a => a.PreferredMibSetId)
                .FirstOrDefaultAsync(cancellationToken);
        }

        var labeled = new List<SnmpTrapVarbind>();
        var labels = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var varbind in message.Varbinds)
        {
            var lookup = await mibLookup.LookupAsync(mibSetId, varbind.Oid, cancellationToken)
                ?? await mibLookup.LookupAsync(varbind.Oid, cancellationToken);
            labels[varbind.Oid] = lookup?.SymbolicName;
            labeled.Add(varbind with { Label = lookup?.SymbolicName });
        }

        var enriched = message with { AgentId = agentId, Varbinds = labeled };
        db.SnmpTrapLogEntries.Add(new SnmpTrapLogEntry
        {
            AgentId = enriched.AgentId,
            SourceAddress = enriched.SourceAddress,
            TrapOid = enriched.TrapOid,
            ReceivedAt = enriched.ReceivedAt.UtcDateTime,
            VarbindsJson = JsonSerializer.Serialize(enriched.Varbinds, JsonOptions),
            MibLabelsJson = JsonSerializer.Serialize(labels, JsonOptions),
            RawPayload = enriched.RawPayload
        });
        await db.SaveChangesAsync(cancellationToken);

        await pubSub.PublishAsync($"evt:snmp-trap:{enriched.AgentId}:{enriched.TrapOid}", enriched, cancellationToken);
        return enriched;
    }

    private async Task<(string? AgentId, int? PreferredMibSetId)> ResolveAgentContextBySourceAsync(string sourceAddress, CancellationToken cancellationToken)
    {
        var host = sourceAddress.Split(':', StringSplitOptions.TrimEntries).FirstOrDefault() ?? sourceAddress;
        var agent = await db.SnmpAgentConfigs.AsNoTracking()
            .FirstOrDefaultAsync(a => a.Host == host, cancellationToken);
        return (agent?.AgentId, agent?.PreferredMibSetId);
    }
}
