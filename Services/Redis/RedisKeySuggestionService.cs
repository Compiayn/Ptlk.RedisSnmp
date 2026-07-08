using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Services.Autocomplete;
using StackExchange.Redis;

namespace Ptlk.RedisSnmp.Services.Redis;

public sealed record RedisKeySuggestion(string RedisKey);

public sealed class RedisKeySuggestionService(
    RedisConnectionFactory redis,
    IOptions<RedisOptions> options)
{
    public async Task<SuggestionPage<RedisKeySuggestion>> SearchPointKeysAsync(
        string query,
        int limit = 24,
        long cursor = 0,
        int pageOffset = 0,
        CancellationToken cancellationToken = default)
    {
        var normalizedQuery = query.Trim();
        if (string.IsNullOrWhiteSpace(normalizedQuery))
        {
            return new SuggestionPage<RedisKeySuggestion>([], false);
        }

        var boundedLimit = Math.Clamp(limit, 1, 100);
        var boundedCursor = Math.Max(cursor, 0L);
        var boundedPageOffset = Math.Max(pageOffset, 0);
        var connection = await redis.GetConnectionAsync(cancellationToken);
        var server = GetServer(connection);
        var databaseIndex = options.Value.DatabaseIndex;
        var filter = BuildPointKeyFilter(normalizedQuery);
        var suggestions = new List<RedisKeySuggestion>(boundedLimit);
        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var nextCursor = boundedCursor;
        var nextPageOffset = boundedPageOffset;
        var hasMore = false;

        var keys = server.Keys(
            databaseIndex,
            "point:*",
            pageSize: Math.Max(boundedLimit * 4, 100),
            cursor: boundedCursor,
            pageOffset: boundedPageOffset);
        using var enumerator = keys.GetEnumerator();
        var scanningCursor = enumerator as IScanningCursor ?? keys as IScanningCursor;

        while (suggestions.Count < boundedLimit && enumerator.MoveNext())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var keyText = enumerator.Current.ToString();
            if (scanningCursor is not null)
            {
                nextCursor = scanningCursor.Cursor;
                nextPageOffset = scanningCursor.PageOffset;
            }

            if (keyText.StartsWith("point:", StringComparison.OrdinalIgnoreCase)
                && MatchesFilter(keyText, filter)
                && seenKeys.Add(keyText))
            {
                suggestions.Add(new RedisKeySuggestion(keyText));
            }
        }

        if (scanningCursor is not null)
        {
            hasMore = nextCursor != 0 || nextPageOffset != 0;
        }

        var items = suggestions
            .OrderBy(suggestion => suggestion.RedisKey, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new SuggestionPage<RedisKeySuggestion>(
            items,
            hasMore,
            NextCursor: nextCursor,
            NextPageOffset: nextPageOffset);
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

    private static string BuildPointKeyFilter(string query)
    {
        var tail = query.StartsWith("point:", StringComparison.OrdinalIgnoreCase)
            ? query["point:".Length..]
            : query;

        return tail.Trim();
    }

    private static bool MatchesFilter(string key, string filter) =>
        string.IsNullOrWhiteSpace(filter)
        || key["point:".Length..].Contains(filter, StringComparison.OrdinalIgnoreCase);
}
