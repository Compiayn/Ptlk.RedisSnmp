using Ptlk.RedisSnmp.Contracts.Trap;
using Ptlk.RedisSnmp.Services.Paths;

namespace Ptlk.RedisSnmp.Services.Trap;

public sealed class TrapParser(SnmpSourcePathService paths)
{
    public SnmpTrapMessage Parse(string raw, string? sourceAddress = null, string? agentId = null)
    {
        var lines = raw.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var source = ParseSource(sourceAddress ?? "unknown");
        var trapOid = "";
        string? version = null;
        string? community = null;
        string? securityName = null;
        string? securityLevel = null;
        string? engineId = null;
        var varbinds = new List<SnmpTrapVarbind>();

        foreach (var line in lines)
        {
            if (line.StartsWith("source=", StringComparison.OrdinalIgnoreCase))
            {
                source = ParseSource(line["source=".Length..].Trim());
                continue;
            }
            if (line.StartsWith("trapOid=", StringComparison.OrdinalIgnoreCase))
            {
                trapOid = Normalize(line["trapOid=".Length..]);
                continue;
            }
            if (line.StartsWith("version=", StringComparison.OrdinalIgnoreCase))
            {
                version = line["version=".Length..].Trim();
                continue;
            }
            if (line.StartsWith("community=", StringComparison.OrdinalIgnoreCase))
            {
                community = line["community=".Length..].Trim();
                continue;
            }
            if (line.StartsWith("securityName=", StringComparison.OrdinalIgnoreCase))
            {
                securityName = line["securityName=".Length..].Trim();
                continue;
            }
            if (line.StartsWith("securityLevel=", StringComparison.OrdinalIgnoreCase))
            {
                securityLevel = line["securityLevel=".Length..].Trim();
                continue;
            }
            if (line.StartsWith("engineId=", StringComparison.OrdinalIgnoreCase))
            {
                engineId = line["engineId=".Length..].Trim();
                continue;
            }

            var parsed = ParseVarbind(line);
            if (parsed is not null)
            {
                if (parsed.Oid is "1.3.6.1.6.3.1.1.4.1.0" or "1.3.6.1.6.3.1.1.4.1")
                {
                    trapOid = Normalize(parsed.Value ?? trapOid);
                }
                varbinds.Add(parsed);
            }
        }

        return new SnmpTrapMessage(
            agentId ?? "unknown",
            source.Address,
            trapOid,
            varbinds,
            DateTimeOffset.UtcNow,
            raw)
        {
            SourcePort = source.Port,
            Version = version,
            Community = community,
            SecurityName = securityName,
            SecurityLevel = securityLevel,
            EngineId = engineId
        };
    }

    private SnmpTrapVarbind? ParseVarbind(string line)
    {
        var parts = line.Split(" = ", 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2)
        {
            parts = line.Split(' ', 2, StringSplitOptions.TrimEntries);
        }
        if (parts.Length != 2)
        {
            return null;
        }

        var oid = Normalize(parts[0]);
        var syntax = "";
        var value = parts[1];
        var colon = value.IndexOf(':', StringComparison.Ordinal);
        if (colon >= 0)
        {
            syntax = value[..colon].Trim();
            value = value[(colon + 1)..].Trim();
        }

        return new SnmpTrapVarbind(oid, value, string.IsNullOrWhiteSpace(syntax) ? null : syntax, null);
    }

    private string Normalize(string oid)
    {
        try
        {
            return paths.NormalizeNumericOid(oid);
        }
        catch
        {
            return oid.Trim().TrimStart('.');
        }
    }

    private static (string Address, int? Port) ParseSource(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.StartsWith("[", StringComparison.Ordinal))
        {
            var end = trimmed.IndexOf(']');
            if (end > 0)
            {
                var address = trimmed[1..end];
                var rest = trimmed[(end + 1)..].TrimStart(':');
                return (address, int.TryParse(rest, out var port) ? port : null);
            }
        }

        var lastColon = trimmed.LastIndexOf(':');
        if (lastColon > 0 && trimmed.IndexOf(':') == lastColon)
        {
            var address = trimmed[..lastColon];
            var portText = trimmed[(lastColon + 1)..];
            if (int.TryParse(portText, out var port))
            {
                return (address, port);
            }
        }

        return (trimmed, null);
    }
}
