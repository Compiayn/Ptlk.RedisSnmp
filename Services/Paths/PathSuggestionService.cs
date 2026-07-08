using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Data;
using System.Text;

namespace Ptlk.RedisSnmp.Services.Paths;

public sealed record SourcePathSuggestion(
    string SourcePath,
    string PointName,
    string? MibLabel,
    string NumericOid,
    string? MibModule,
    string? MibSyntax,
    string? MibAccess);

public sealed class PathSuggestionService(AppDbContext db)
{
    public async Task<IReadOnlyList<SourcePathSuggestion>> SearchSnmpPointSuggestionsAsync(
        string query,
        int limit = 24,
        CancellationToken cancellationToken = default)
    {
        var normalizedQuery = query.Trim();
        if (string.IsNullOrWhiteSpace(normalizedQuery))
        {
            return [];
        }

        var boundedLimit = Math.Clamp(limit, 1, 100);
        var pattern = $"%{EscapeLikePattern(normalizedQuery)}%";

        return await db.SnmpPointConfigs
            .AsNoTracking()
            .Where(point =>
                EF.Functions.Like(point.PointName, pattern, "\\")
                || (point.MibLabel != null && EF.Functions.Like(point.MibLabel, pattern, "\\")))
            .OrderBy(point => point.MibLabel ?? point.PointName)
            .ThenBy(point => point.PointName)
            .ThenBy(point => point.SourcePath)
            .Select(point => new SourcePathSuggestion(
                point.SourcePath,
                point.PointName,
                point.MibLabel,
                point.NumericOid,
                point.MibModule,
                point.MibSyntax,
                point.MibAccess))
            .Take(boundedLimit)
            .ToListAsync(cancellationToken);
    }

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

    private static string EscapeLikePattern(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var character in value)
        {
            if (character is '%' or '_' or '\\')
            {
                builder.Append('\\');
            }

            builder.Append(character);
        }

        return builder.ToString();
    }
}
