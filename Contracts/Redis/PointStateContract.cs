namespace Ptlk.RedisSnmp.Contracts.Redis;

public sealed record PointStateContract(
    string Key,
    string? Value,
    string Quality,
    string? Type,
    long Timestamp,
    long Version,
    string Source,
    string? Access,
    string? Unit);
