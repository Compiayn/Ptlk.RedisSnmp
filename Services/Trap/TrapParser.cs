using Ptlk.RedisSnmp.Contracts.Trap;
using Ptlk.RedisSnmp.Services.Paths;

namespace Ptlk.RedisSnmp.Services.Trap;

public sealed class TrapParser(SnmpSourcePathService paths)
{
    public SnmpTrapMessage Parse(string raw, string? sourceAddress = null, string? agentId = null)
    {
        var lines = raw.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var source = sourceAddress ?? "unknown";
        var trapOid = "0";
        var varbinds = new List<SnmpTrapVarbind>();

        foreach (var line in lines)
        {
            if (line.StartsWith("source=", StringComparison.OrdinalIgnoreCase))
            {
                source = line["source=".Length..].Trim();
                continue;
            }
            if (line.StartsWith("trapOid=", StringComparison.OrdinalIgnoreCase))
            {
                trapOid = Normalize(line["trapOid=".Length..]);
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
            source,
            trapOid,
            varbinds,
            DateTimeOffset.UtcNow,
            raw);
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
}
