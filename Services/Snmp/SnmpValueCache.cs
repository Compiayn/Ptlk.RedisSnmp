using System.Collections.Concurrent;
using Ptlk.RedisSnmp.Contracts.Snmp;

namespace Ptlk.RedisSnmp.Services.Snmp;

public sealed record SnmpCachedValue(
    string SourcePath,
    string AgentId,
    string NumericOid,
    string? Value,
    string Quality,
    DateTimeOffset Timestamp,
    string? RawValue,
    string? LastErrorCode,
    string? LastErrorMessage);

public sealed class SnmpValueCache
{
    private readonly ConcurrentDictionary<string, SnmpCachedValue> _values = new(StringComparer.OrdinalIgnoreCase);

    public void Set(SnmpCachedValue value)
    {
        _values[value.SourcePath] = value;
    }

    public SnmpCachedValue? Get(string sourcePath) =>
        _values.TryGetValue(sourcePath, out var value) ? value : null;

    public IReadOnlyList<SnmpCachedValue> Snapshot() =>
        _values.Values.OrderBy(value => value.SourcePath).ToList();

    public void MarkAgentBad(
        string agentId,
        IEnumerable<(string SourcePath, string NumericOid)> points,
        string errorCode,
        string errorMessage)
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var point in points)
        {
            Set(new SnmpCachedValue(
                point.SourcePath,
                agentId,
                point.NumericOid,
                Value: null,
                Quality: SnmpQuality.Bad,
                Timestamp: now,
                RawValue: null,
                LastErrorCode: errorCode,
                LastErrorMessage: errorMessage));
        }
    }
}
