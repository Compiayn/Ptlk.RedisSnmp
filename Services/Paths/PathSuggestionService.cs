using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Services.Autocomplete;
using System.Text;

namespace Ptlk.RedisSnmp.Services.Paths;

public sealed record SourcePathSuggestion(
    string SourcePath,
    string? MibLabel,
    string NumericOid,
    string? MibModule,
    string? MibSyntax,
    string? MibAccess);

public sealed class PathSuggestionService(AppDbContext db)
{
    public async Task<SuggestionPage<SourcePathSuggestion>> SearchSnmpPointSuggestionsAsync(
        string query,
        int limit = 24,
        int offset = 0,
        CancellationToken cancellationToken = default)
    {
        var normalizedQuery = query.Trim();
        if (string.IsNullOrWhiteSpace(normalizedQuery))
        {
            return new SuggestionPage<SourcePathSuggestion>([], false);
        }

        var boundedLimit = Math.Clamp(limit, 1, 100);
        var boundedOffset = Math.Max(offset, 0);
        var searchSourcePath = normalizedQuery.StartsWith("snmp:", StringComparison.OrdinalIgnoreCase);
        var normalizedQueryLower = normalizedQuery.ToLowerInvariant();
        var pattern = $"%{EscapeLikePattern(normalizedQueryLower)}%";

        var results = await db.SnmpPointConfigs
            .AsNoTracking()
            .Where(point =>
                (searchSourcePath && EF.Functions.Like(point.SourcePath.ToLower(), pattern, "\\"))
                || (point.MibLabel != null && EF.Functions.Like(point.MibLabel.ToLower(), pattern, "\\")))
            .OrderBy(point => point.MibLabel ?? point.NumericOid)
            .ThenBy(point => point.SourcePath)
            .Skip(boundedOffset)
            .Select(point => new SourcePathSuggestion(
                point.SourcePath,
                point.MibLabel,
                point.NumericOid,
                point.MibModule,
                point.MibSyntax,
                point.MibAccess))
            .Take(boundedLimit + 1)
            .ToListAsync(cancellationToken);

        var items = results.Take(boundedLimit).ToList();
        return new SuggestionPage<SourcePathSuggestion>(
            items,
            results.Count > boundedLimit,
            boundedOffset + items.Count);
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
