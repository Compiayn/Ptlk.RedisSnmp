namespace Ptlk.RedisSnmp.Services.Autocomplete;

public sealed record SuggestionPage<T>(
    IReadOnlyList<T> Items,
    bool HasMore,
    int NextOffset = 0,
    long NextCursor = 0,
    int NextPageOffset = 0);
