using System.Collections.Concurrent;

namespace Ptlk.RedisSnmp.Services.Expressions;

public sealed record ExpressionPointValue(
    string? Value,
    string Quality,
    long Timestamp,
    string? Error);

public sealed class ExpressionValueCache
{
    private readonly ConcurrentDictionary<string, ExpressionPointValue> cache = new(StringComparer.OrdinalIgnoreCase);

    public void Set(string sourcePath, string? value, string quality, string? error = null) =>
        cache[sourcePath] = new ExpressionPointValue(
            value,
            quality,
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            error);

    public ExpressionPointValue? Get(string sourcePath) =>
        cache.TryGetValue(sourcePath, out var value) ? value : null;
}
