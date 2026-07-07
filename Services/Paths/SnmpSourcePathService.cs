using System.Text.RegularExpressions;

namespace Ptlk.RedisSnmp.Services.Paths;

public sealed class SnmpSourcePathService
{
    private static readonly Regex NumericOidPattern = new(@"^\d+(\.\d+)*$", RegexOptions.Compiled);

    public bool IsSafeAgentId(string? agentId) =>
        !string.IsNullOrWhiteSpace(agentId)
        && !agentId.Contains(':', StringComparison.Ordinal)
        && !agentId.Contains('*', StringComparison.Ordinal)
        && !agentId.Contains('/', StringComparison.Ordinal)
        && !agentId.Contains('\\', StringComparison.Ordinal)
        && !agentId.Any(char.IsWhiteSpace);

    public string NormalizeNumericOid(string oid)
    {
        var normalized = oid.Trim().TrimStart('.');
        if (!NumericOidPattern.IsMatch(normalized))
        {
            throw new InvalidOperationException($"OID '{oid}' must be numeric.");
        }

        return normalized;
    }

    public string BuildPointSourcePath(string agentId, string numericOid)
    {
        if (!IsSafeAgentId(agentId))
        {
            throw new InvalidOperationException("AgentId must not contain ':', '*', '/', '\\', or whitespace.");
        }

        return $"snmp:{agentId}/{NormalizeNumericOid(numericOid)}";
    }

    public bool TryParsePointSourcePath(
        string sourcePath,
        out string agentId,
        out string numericOid)
    {
        agentId = "";
        numericOid = "";
        if (!sourcePath.StartsWith("snmp:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var payload = sourcePath["snmp:".Length..];
        var parts = payload.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 2 || !IsSafeAgentId(parts[0]))
        {
            return false;
        }

        try
        {
            agentId = parts[0];
            numericOid = NormalizeNumericOid(parts[1]);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
