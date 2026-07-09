using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Contracts.Trap;
using Ptlk.RedisSnmp.Services.Paths;

namespace Ptlk.RedisSnmp.Services.Trap;

public sealed class TrapParser(SnmpSourcePathService paths)
{
    public SnmpTrapMessage Parse(string raw, string? sourceAddress = null, string? agentId = null)
    {
        var lines = raw.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .SelectMany(ExpandLine)
            .ToArray();
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
            if (TryParseTransportSource(line, out var transportSource))
            {
                source = transportSource;
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
            if (line.StartsWith("security=", StringComparison.OrdinalIgnoreCase))
            {
                ApplySecurity(
                    line["security=".Length..].Trim(),
                    ref version,
                    ref community,
                    ref securityName,
                    ref securityLevel,
                    ref engineId);
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
                if (IsTrapOidVarbind(parsed.Oid))
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

    private static IEnumerable<string> ExpandLine(string line)
    {
        if (line.StartsWith("source=", StringComparison.OrdinalIgnoreCase)
            && line.Contains('|', StringComparison.Ordinal))
        {
            return line.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        return [line];
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

    private static void ApplySecurity(
        string value,
        ref string? version,
        ref string? community,
        ref string? securityName,
        ref string? securityLevel,
        ref string? engineId)
    {
        var security = value.Trim();
        if (string.IsNullOrWhiteSpace(security))
        {
            return;
        }

        version ??= InferVersion(security);
        community ??= ExtractNamedValue(security, "community") ?? security;
        securityName ??= ExtractNamedValue(security, "securityName")
                         ?? ExtractNamedValue(security, "user")
                         ?? (version == SnmpVersions.V3 ? security : null);
        securityLevel ??= ExtractNamedValue(security, "securityLevel")
                          ?? ExtractNamedValue(security, "level");
        engineId ??= ExtractNamedValue(security, "engineId")
                     ?? ExtractNamedValue(security, "engineID");
    }

    private static string? InferVersion(string value)
    {
        if (value.Contains("v1", StringComparison.OrdinalIgnoreCase)
            || value.Contains("version 1", StringComparison.OrdinalIgnoreCase))
        {
            return SnmpVersions.V1;
        }

        if (value.Contains("v2c", StringComparison.OrdinalIgnoreCase)
            || value.Contains("version 2", StringComparison.OrdinalIgnoreCase))
        {
            return SnmpVersions.V2C;
        }

        if (value.Contains("v3", StringComparison.OrdinalIgnoreCase)
            || value.Contains("version 3", StringComparison.OrdinalIgnoreCase))
        {
            return SnmpVersions.V3;
        }

        return null;
    }

    private static string? ExtractNamedValue(string value, string name)
    {
        foreach (var token in value.Split([' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (token.StartsWith(name + "=", StringComparison.OrdinalIgnoreCase)
                || token.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
            {
                return token[(name.Length + 1)..].Trim().Trim('"', '\'');
            }
        }

        var marker = value.IndexOf(name, StringComparison.OrdinalIgnoreCase);
        if (marker < 0)
        {
            return null;
        }

        var remainder = value[(marker + name.Length)..].TrimStart(' ', ':', '=');
        if (string.IsNullOrWhiteSpace(remainder))
        {
            return null;
        }

        return remainder.Split([' ', ',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault()
            ?.Trim('"', '\'');
    }

    private static bool IsTrapOidVarbind(string oid) =>
        oid is "1.3.6.1.6.3.1.1.4.1.0" or "1.3.6.1.6.3.1.1.4.1"
        || oid.EndsWith("snmpTrapOID.0", StringComparison.OrdinalIgnoreCase)
        || oid.EndsWith("snmpTrapOID", StringComparison.OrdinalIgnoreCase);

    private static bool TryParseTransportSource(string value, out (string Address, int? Port) source)
    {
        var trimmed = value.Trim();
        var udpIndex = trimmed.IndexOf("UDP:", StringComparison.OrdinalIgnoreCase);
        if (udpIndex < 0)
        {
            source = default;
            return false;
        }

        source = ParseSource(trimmed[udpIndex..]);
        return !string.IsNullOrWhiteSpace(source.Address);
    }

    private static (string Address, int? Port) ParseSource(string value)
    {
        var trimmed = value.Trim();
        var transport = trimmed.IndexOf(':');
        if (transport > 0
            && trimmed[..transport].All(char.IsLetter)
            && trimmed.Length > transport + 1)
        {
            trimmed = trimmed[(transport + 1)..].Trim();
        }

        var arrow = trimmed.IndexOf("->", StringComparison.Ordinal);
        if (arrow > 0)
        {
            trimmed = trimmed[..arrow].Trim();
        }

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
