using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Models;

namespace Ptlk.RedisSnmp.Services.Snmp;

public sealed class SnmpQualityPolicy
{
    private static readonly HashSet<string> AgentLevelErrors = new(StringComparer.OrdinalIgnoreCase)
    {
        SnmpOperationStatus.Timeout,
        SnmpOperationStatus.AuthFailure,
        SnmpOperationStatus.ToolMissing
    };

    public bool IsAgentLevelFailure(SnmpGetResult result) =>
        !result.Success
        && result.ErrorCode is not null
        && AgentLevelErrors.Contains(result.ErrorCode);

    public SnmpPollPointResult FromGetResult(SnmpPointConfig point, SnmpGetResult result)
    {
        if (result.Success)
        {
            return new SnmpPollPointResult(
                point.SourcePath,
                result.Value,
                SnmpQuality.Good,
                null,
                null,
                result.Value);
        }

        return new SnmpPollPointResult(
            point.SourcePath,
            null,
            SnmpQuality.Bad,
            result.ErrorCode ?? SnmpOperationStatus.Failed,
            result.ErrorMessage ?? "SNMP Get failed.",
            null);
    }

    public SnmpPollPointResult DecodeFailure(SnmpPointConfig point, string message) =>
        new(point.SourcePath, null, SnmpQuality.Bad, SnmpOperationStatus.DecodeFailed, message, null);
}
