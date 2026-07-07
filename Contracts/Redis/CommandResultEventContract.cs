using System.Text.Json;

namespace Ptlk.RedisSnmp.Contracts.Redis;

public sealed record CommandResultEventContract(
    int Schema,
    string Type,
    string MessageId,
    string CommandId,
    string Key,
    bool Success,
    JsonElement? ActualValue,
    long? Version,
    string? ErrorCode,
    string? ErrorMessage,
    long Timestamp,
    string Source);
