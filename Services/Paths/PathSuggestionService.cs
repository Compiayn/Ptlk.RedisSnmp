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
    string? MibAccess,
    string Kind = "SNMP");

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
        var searchSnmpSourcePath = normalizedQuery.StartsWith("snmp:", StringComparison.OrdinalIgnoreCase);
        var searchExpressionSourcePath = normalizedQuery.StartsWith("exp:", StringComparison.OrdinalIgnoreCase);
        var normalizedQueryLower = normalizedQuery.ToLowerInvariant();
        var pattern = $"%{EscapeLikePattern(normalizedQueryLower)}%";
        var scanLimit = Math.Clamp(boundedOffset + boundedLimit + 25, boundedLimit + 1, 500);

        var pointResults = await db.SnmpPointConfigs
            .AsNoTracking()
            .Where(point =>
                (searchSnmpSourcePath && EF.Functions.Like(point.SourcePath.ToLower(), pattern, "\\"))
                || (point.MibLabel != null && EF.Functions.Like(point.MibLabel.ToLower(), pattern, "\\")))
            .OrderBy(point => point.MibLabel ?? point.NumericOid)
            .ThenBy(point => point.SourcePath)
            .Select(point => new SourcePathSuggestion(
                point.SourcePath,
                point.MibLabel,
                point.NumericOid,
                point.MibModule,
                point.MibSyntax,
                point.MibAccess,
                "SNMP"))
            .Take(scanLimit)
            .ToListAsync(cancellationToken);

        var expressionResults = await db.ExpressionConfigs
            .AsNoTracking()
            .Where(expression =>
                EF.Functions.Like(expression.Name.ToLower(), pattern, "\\")
                || (searchExpressionSourcePath && EF.Functions.Like(("exp:" + expression.Name).ToLower(), pattern, "\\")))
            .OrderBy(expression => expression.Name)
            .Select(expression => new SourcePathSuggestion(
                $"exp:{expression.Name}",
                expression.Name,
                "",
                null,
                expression.ValueType,
                expression.Rw,
                "Expression"))
            .Take(scanLimit)
            .ToListAsync(cancellationToken);

        var results = pointResults
            .Concat(expressionResults)
            .OrderBy(item => item.Kind)
            .ThenBy(item => item.MibLabel ?? item.NumericOid)
            .ThenBy(item => item.SourcePath)
            .Skip(boundedOffset)
            .Take(boundedLimit + 1)
            .ToList();

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

        var expressionPaths = await db.ExpressionConfigs
            .AsNoTracking()
            .OrderBy(expression => expression.Name)
            .Select(expression => $"exp:{expression.Name}")
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

        return pointPaths.Concat(expressionPaths).Concat(agentHealth).ToList();
    }

    public async Task<IReadOnlyList<string>> GetExpressionBindingSourcePathSuggestionsAsync(CancellationToken cancellationToken = default)
    {
        var pointPaths = await db.SnmpPointConfigs
            .AsNoTracking()
            .OrderBy(point => point.SourcePath)
            .Select(point => point.SourcePath)
            .ToListAsync(cancellationToken);

        var expressionPaths = await db.ExpressionConfigs
            .AsNoTracking()
            .OrderBy(expression => expression.Name)
            .Select(expression => $"exp:{expression.Name}")
            .ToListAsync(cancellationToken);

        return pointPaths
            .Concat(expressionPaths)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(path => path)
            .Take(500)
            .ToList();
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
