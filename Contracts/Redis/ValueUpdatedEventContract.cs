namespace Ptlk.RedisSnmp.Contracts.Redis;

public sealed record ValueUpdatedEventContract(
    int Schema,
    string Type,
    string MessageId,
    string Key,
    string? Value,
    string Quality,
    long Version,
    long Timestamp,
    string Source);
