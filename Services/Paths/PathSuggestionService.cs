using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Data;

namespace Ptlk.RedisSnmp.Services.Paths;

public sealed class PathSuggestionService(AppDbContext db)
{
    public async Task<IReadOnlyList<string>> ListSourcePathsAsync(CancellationToken cancellationToken = default)
    {
        var pointPaths = await db.SnmpPointConfigs
            .AsNoTracking()
            .OrderBy(point => point.SourcePath)
            .Select(point => point.SourcePath)
            .ToListAsync(cancellationToken);

        var agentIds = await db.SnmpAgentConfigs
            .AsNoTracking()
            .OrderBy(agent => agent.AgentId)
            .Select(agent => agent.AgentId)
            .ToListAsync(cancellationToken);
        var agentHealth = agentIds.SelectMany(agentId => new[]
        {
            $"snmp-health:{agentId}/reachable",
            $"snmp-health:{agentId}/lastPollMs",
            $"snmp-health:{agentId}/errorCount"
        });

        return pointPaths.Concat(agentHealth).ToList();
    }
}
