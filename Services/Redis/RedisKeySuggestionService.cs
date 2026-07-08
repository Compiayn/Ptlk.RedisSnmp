using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using StackExchange.Redis;
using System.Text;

namespace Ptlk.RedisSnmp.Services.Redis;

public sealed record RedisKeySuggestion(string RedisKey);

public sealed class RedisKeySuggestionService(
    RedisConnectionFactory redis,
    IOptions<RedisOptions> options)
{
    public async Task<IReadOnlyList<RedisKeySuggestion>> SearchPointKeysAsync(
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
        var connection = await redis.GetConnectionAsync(cancellationToken);
        var server = GetServer(connection);
        var databaseIndex = options.Value.DatabaseIndex;
        var pattern = BuildPointKeyPattern(normalizedQuery);
        var suggestions = new List<RedisKeySuggestion>(boundedLimit);

        foreach (var key in server.Keys(databaseIndex, pattern, pageSize: boundedLimit))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var keyText = key.ToString();
            if (keyText.StartsWith("point:", StringComparison.OrdinalIgnoreCase))
            {
                suggestions.Add(new RedisKeySuggestion(keyText));
            }

            if (suggestions.Count >= boundedLimit)
            {
                break;
            }
        }

        return suggestions
            .OrderBy(suggestion => suggestion.RedisKey, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static IServer GetServer(IConnectionMultiplexer connection)
    {
        foreach (var endpoint in connection.GetEndPoints())
        {
            var server = connection.GetServer(endpoint);
            if (server.IsConnected)
            {
                return server;
            }
        }

        throw new InvalidOperationException("No connected Redis server is available for key suggestions.");
    }

    private static RedisValue BuildPointKeyPattern(string query)
    {
        var tail = query.StartsWith("point:", StringComparison.OrdinalIgnoreCase)
            ? query["point:".Length..]
            : query;

        if (string.IsNullOrWhiteSpace(tail))
        {
            return "point:*";
        }

        return $"point:*{EscapeRedisPattern(tail)}*";
    }

    private static string EscapeRedisPattern(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var character in value)
        {
            if (character is '*' or '?' or '[' or ']' or '\\')
            {
                builder.Append('\\');
            }

            builder.Append(character);
        }

        return builder.ToString();
    }
}
