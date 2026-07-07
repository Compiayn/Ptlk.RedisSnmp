using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Models;

namespace Ptlk.RedisSnmp.Services.Snmp;

public sealed class NetSnmpArgumentBuilder(SnmpCredentialService credentials)
{
    public NetSnmpCommandArguments BuildGet(SnmpAgentConfig agent, SnmpCredentialConfig? credential, string numericOid) =>
        BuildBase("snmpget", agent, credential, [NormalizeCliOid(numericOid)]);

    public NetSnmpCommandArguments BuildWalk(SnmpAgentConfig agent, SnmpCredentialConfig? credential, string rootOid) =>
        BuildBase("snmpwalk", agent, credential, [NormalizeCliOid(rootOid)]);

    public NetSnmpCommandArguments BuildSet(
        SnmpAgentConfig agent,
        SnmpCredentialConfig? credential,
        string numericOid,
        string valueType,
        string value) =>
        BuildBase("snmpset", agent, credential, [NormalizeCliOid(numericOid), ToSetType(valueType), value]);

    public NetSnmpCommandArguments BuildTranslate(string input, bool numeric = true)
    {
        var args = numeric ? new[] { "-On", input } : new[] { input };
        return new NetSnmpCommandArguments("snmptranslate", args, args);
    }

    public NetSnmpCommandArguments BuildTrapDaemon(int listenPort, string configPath)
    {
        var args = new[] { "-f", "-Lo", "-On", "-C", "-c", configPath, $"udp:{listenPort}" };
        return new NetSnmpCommandArguments("snmptrapd", args, args);
    }

    private NetSnmpCommandArguments BuildBase(
        string tool,
        SnmpAgentConfig agent,
        SnmpCredentialConfig? credential,
        IReadOnlyList<string> tail)
    {
        var version = agent.SnmpVersion;
        var args = new List<string> { "-v", version, "-t", Seconds(agent.TimeoutMs), "-r", agent.RetryCount.ToString() };
        var redacted = new List<string>(args);
        var secrets = credential is null ? new SnmpCredentialSecrets(null, null, null) : credentials.RevealSecrets(credential);

        if (version is SnmpVersions.V1 or SnmpVersions.V2C)
        {
            args.AddRange(["-c", secrets.Community ?? "public"]);
            redacted.AddRange(["-c", "***"]);
        }
        else if (version == SnmpVersions.V3)
        {
            args.AddRange(["-l", credential?.SecurityLevel ?? SnmpSecurityLevels.NoAuthNoPriv]);
            redacted.AddRange(["-l", credential?.SecurityLevel ?? SnmpSecurityLevels.NoAuthNoPriv]);
            if (!string.IsNullOrWhiteSpace(credential?.SecurityName))
            {
                args.AddRange(["-u", credential.SecurityName]);
                redacted.AddRange(["-u", credential.SecurityName]);
            }
            if (!string.IsNullOrWhiteSpace(credential?.AuthProtocol))
            {
                args.AddRange(["-a", credential.AuthProtocol]);
                redacted.AddRange(["-a", credential.AuthProtocol]);
            }
            if (!string.IsNullOrWhiteSpace(secrets.AuthPassword))
            {
                args.AddRange(["-A", secrets.AuthPassword]);
                redacted.AddRange(["-A", "***"]);
            }
            if (!string.IsNullOrWhiteSpace(credential?.PrivProtocol))
            {
                args.AddRange(["-x", credential.PrivProtocol]);
                redacted.AddRange(["-x", credential.PrivProtocol]);
            }
            if (!string.IsNullOrWhiteSpace(secrets.PrivPassword))
            {
                args.AddRange(["-X", secrets.PrivPassword]);
                redacted.AddRange(["-X", "***"]);
            }
        }

        var endpoint = agent.Port == 161 ? agent.Host : $"{agent.Host}:{agent.Port}";
        args.Add(endpoint);
        redacted.Add(endpoint);
        args.AddRange(tail);
        redacted.AddRange(tail);

        return new NetSnmpCommandArguments(tool, args, redacted);
    }

    private static string Seconds(int milliseconds) =>
        Math.Max(1, (int)Math.Ceiling(milliseconds / 1000m)).ToString();

    private static string NormalizeCliOid(string numericOid) =>
        numericOid.StartsWith('.') ? numericOid : "." + numericOid;

    private static string ToSetType(string valueType) =>
        valueType switch
        {
            SnmpValueTypes.Integer => "i",
            SnmpValueTypes.Double => "d",
            SnmpValueTypes.Boolean => "i",
            SnmpValueTypes.Timeticks => "t",
            SnmpValueTypes.Oid => "o",
            _ => "s"
        };
}
