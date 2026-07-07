using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Logs;

namespace Ptlk.RedisSnmp.Services.Snmp;

public sealed class SnmpClientService(
    NetSnmpArgumentBuilder arguments,
    INetSnmpProcessRunner runner,
    LogService log,
    IOptions<SnmpRuntimeOptions> runtimeOptions)
{
    private static readonly Regex ValueLinePattern = new(@"^(?<oid>\.?[0-9][0-9.]*|[^=\s]+)\s+=\s+(?<syntax>[^:]+):\s*(?<value>.*)$", RegexOptions.Compiled);

    public async Task<SnmpGetResult> GetAsync(
        SnmpAgentConfig agent,
        SnmpCredentialConfig? credential,
        string numericOid,
        CancellationToken cancellationToken = default)
    {
        var process = await runner.RunAsync(
            arguments.BuildGet(agent, credential, numericOid),
            TimeSpan.FromMilliseconds(agent.TimeoutMs > 0 ? agent.TimeoutMs : runtimeOptions.Value.DefaultTimeoutMs),
            cancellationToken);
        var result = ParseGetOrSet(numericOid, process);
        await log.AddSnmpAsync(
            agent.AgentId,
            numericOid,
            "get",
            result.Success ? "Info" : "Warning",
            result.Success ? $"SNMP Get succeeded for {numericOid}." : result.ErrorMessage ?? "SNMP Get failed.",
            null,
            result.ErrorCode,
            (int)process.Duration.TotalMilliseconds,
            cancellationToken);
        return result;
    }

    public async Task<SnmpWalkResult> WalkAsync(
        SnmpAgentConfig agent,
        SnmpCredentialConfig? credential,
        string rootOid,
        CancellationToken cancellationToken = default)
    {
        var process = await runner.RunAsync(
            arguments.BuildWalk(agent, credential, rootOid),
            TimeSpan.FromMilliseconds(agent.TimeoutMs > 0 ? agent.TimeoutMs : runtimeOptions.Value.DefaultTimeoutMs),
            cancellationToken);
        var result = ParseWalk(process);
        await log.AddSnmpAsync(
            agent.AgentId,
            rootOid,
            "walk",
            result.Success ? "Info" : "Warning",
            result.Success ? $"SNMP Walk returned {result.Items.Count} item(s)." : result.ErrorMessage ?? "SNMP Walk failed.",
            null,
            result.ErrorCode,
            (int)process.Duration.TotalMilliseconds,
            cancellationToken);
        return result;
    }

    public async Task<SnmpSetResult> SetAsync(
        SnmpAgentConfig agent,
        SnmpCredentialConfig? credential,
        SnmpPointConfig point,
        string value,
        string? commandId = null,
        CancellationToken cancellationToken = default)
    {
        var process = await runner.RunAsync(
            arguments.BuildSet(agent, credential, point.NumericOid, point.ValueType, value),
            TimeSpan.FromMilliseconds(agent.TimeoutMs > 0 ? agent.TimeoutMs : runtimeOptions.Value.DefaultTimeoutMs),
            cancellationToken);
        var parsed = ParseGetOrSet(point.NumericOid, process);
        var result = new SnmpSetResult(parsed.Success, parsed.Oid, parsed.Value, parsed.Syntax, parsed.RawOutput, parsed.ErrorCode, parsed.ErrorMessage);
        await log.AddSnmpAsync(
            agent.AgentId,
            point.NumericOid,
            "set",
            result.Success ? "Info" : "Warning",
            result.Success ? $"SNMP Set succeeded for {point.NumericOid}." : result.ErrorMessage ?? "SNMP Set failed.",
            commandId,
            result.ErrorCode,
            (int)process.Duration.TotalMilliseconds,
            cancellationToken);
        return result;
    }

    public async Task<SnmpTranslateResult> TranslateAsync(
        string input,
        CancellationToken cancellationToken = default)
    {
        var process = await runner.RunAsync(
            arguments.BuildTranslate(input),
            TimeSpan.FromMilliseconds(runtimeOptions.Value.DefaultTimeoutMs),
            cancellationToken);

        if (process.ExitCode == 0)
        {
            var line = process.StandardOutput.SplitLines().FirstOrDefault();
            return new SnmpTranslateResult(true, input, NormalizeOidOrNull(line), line, process.StandardOutput, null, null);
        }

        var error = ClassifyError(process);
        return new SnmpTranslateResult(false, input, null, null, process.StandardOutput + process.StandardError, error.Code, error.Message);
    }

    public static SnmpGetResult ParseGetOrSet(string requestedOid, NetSnmpProcessResult process)
    {
        if (process.ExitCode == 0)
        {
            var line = process.StandardOutput.SplitLines().FirstOrDefault(l => !string.IsNullOrWhiteSpace(l));
            if (line is null)
            {
                return new SnmpGetResult(false, requestedOid, null, null, process.StandardOutput, SnmpOperationStatus.DecodeFailed, "SNMP output was empty.");
            }

            var match = ValueLinePattern.Match(line);
            if (!match.Success)
            {
                var noSuch = ClassifyNoSuch(line);
                if (noSuch is not null)
                {
                    return new SnmpGetResult(false, requestedOid, null, null, process.StandardOutput, noSuch.Value.Code, noSuch.Value.Message);
                }

                return new SnmpGetResult(false, requestedOid, null, null, process.StandardOutput, SnmpOperationStatus.DecodeFailed, $"Could not parse SNMP output: {line}");
            }

            return new SnmpGetResult(
                true,
                NormalizeOidOrNull(match.Groups["oid"].Value) ?? requestedOid,
                match.Groups["value"].Value.Trim(),
                match.Groups["syntax"].Value.Trim(),
                process.StandardOutput,
                null,
                null);
        }

        var error = ClassifyError(process);
        return new SnmpGetResult(false, requestedOid, null, null, process.StandardOutput + process.StandardError, error.Code, error.Message);
    }

    public static SnmpWalkResult ParseWalk(NetSnmpProcessResult process)
    {
        if (process.ExitCode != 0)
        {
            var error = ClassifyError(process);
            return new SnmpWalkResult(false, [], process.StandardOutput + process.StandardError, error.Code, error.Message);
        }

        var items = new List<SnmpWalkItem>();
        foreach (var line in process.StandardOutput.SplitLines().Where(l => !string.IsNullOrWhiteSpace(l)))
        {
            var match = ValueLinePattern.Match(line);
            if (!match.Success)
            {
                continue;
            }

            items.Add(new SnmpWalkItem(
                NormalizeOidOrNull(match.Groups["oid"].Value) ?? match.Groups["oid"].Value,
                match.Groups["value"].Value.Trim(),
                match.Groups["syntax"].Value.Trim(),
                line));
        }

        return new SnmpWalkResult(true, items, process.StandardOutput, null, null);
    }

    private static (string Code, string Message) ClassifyError(NetSnmpProcessResult process)
    {
        if (process.TimedOut || process.ErrorCode == SnmpOperationStatus.Timeout)
        {
            return (SnmpOperationStatus.Timeout, "SNMP operation timed out.");
        }

        var text = process.StandardOutput + "\n" + process.StandardError;
        if (text.Contains("Authentication failure", StringComparison.OrdinalIgnoreCase)
            || text.Contains("authorizationError", StringComparison.OrdinalIgnoreCase))
        {
            return (SnmpOperationStatus.AuthFailure, text.Trim());
        }

        var noSuch = ClassifyNoSuch(text);
        if (noSuch is not null)
        {
            return noSuch.Value;
        }

        if (process.ErrorCode == SnmpOperationStatus.ToolMissing)
        {
            return (SnmpOperationStatus.ToolMissing, process.StandardError.Trim());
        }

        return (SnmpOperationStatus.Failed, string.IsNullOrWhiteSpace(text) ? "SNMP operation failed." : text.Trim());
    }

    private static (string Code, string Message)? ClassifyNoSuch(string text)
    {
        if (text.Contains("No Such Object", StringComparison.OrdinalIgnoreCase))
        {
            return (SnmpOperationStatus.NoSuchObject, text.Trim());
        }
        if (text.Contains("No Such Instance", StringComparison.OrdinalIgnoreCase))
        {
            return (SnmpOperationStatus.NoSuchInstance, text.Trim());
        }
        if (text.Contains("No Such Name", StringComparison.OrdinalIgnoreCase)
            || text.Contains("noSuchName", StringComparison.OrdinalIgnoreCase))
        {
            return (SnmpOperationStatus.NoSuchName, text.Trim());
        }

        return null;
    }

    private static string? NormalizeOidOrNull(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var oid = value.Trim().TrimStart('.');
        return oid.All(ch => char.IsDigit(ch) || ch == '.') && oid.Any(char.IsDigit)
            ? oid
            : value.Trim();
    }
}

internal static class SnmpStringExtensions
{
    public static IEnumerable<string> SplitLines(this string value) =>
        value.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n');
}
