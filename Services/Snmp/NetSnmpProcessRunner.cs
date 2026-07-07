using System.Diagnostics;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Snmp;

namespace Ptlk.RedisSnmp.Services.Snmp;

public interface INetSnmpProcessRunner
{
    Task<NetSnmpProcessResult> RunAsync(
        NetSnmpCommandArguments command,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}

public sealed class NetSnmpProcessRunner(
    IOptions<NetSnmpOptions> options,
    ILogger<NetSnmpProcessRunner> logger) : INetSnmpProcessRunner
{
    public async Task<NetSnmpProcessResult> RunAsync(
        NetSnmpCommandArguments command,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        var toolPath = ResolveTool(command.Tool);
        if (toolPath is null)
        {
            return new NetSnmpProcessResult(
                command.Tool,
                command.Arguments,
                command.RedactedArguments,
                ExitCode: -1,
                StandardOutput: "",
                StandardError: $"Net-SNMP tool '{command.Tool}' was not found.",
                Duration: TimeSpan.Zero,
                TimedOut: false,
                ErrorCode: SnmpOperationStatus.ToolMissing);
        }

        var stopwatch = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        using var process = new Process();
        process.StartInfo.FileName = toolPath;
        foreach (var arg in command.Arguments)
        {
            process.StartInfo.ArgumentList.Add(arg);
        }
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.RedirectStandardError = true;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;

        try
        {
            process.Start();
            var stdoutTask = process.StandardOutput.ReadToEndAsync(cts.Token);
            var stderrTask = process.StandardError.ReadToEndAsync(cts.Token);
            await process.WaitForExitAsync(cts.Token);
            stopwatch.Stop();

            return new NetSnmpProcessResult(
                command.Tool,
                command.Arguments,
                command.RedactedArguments,
                process.ExitCode,
                await stdoutTask,
                await stderrTask,
                stopwatch.Elapsed,
                TimedOut: false,
                ErrorCode: process.ExitCode == 0 ? null : SnmpOperationStatus.Failed);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            TryKill(process);
            return new NetSnmpProcessResult(
                command.Tool,
                command.Arguments,
                command.RedactedArguments,
                ExitCode: -1,
                StandardOutput: "",
                StandardError: $"Net-SNMP command timed out after {timeout.TotalMilliseconds:n0} ms.",
                Duration: stopwatch.Elapsed,
                TimedOut: true,
                ErrorCode: SnmpOperationStatus.Timeout);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            logger.LogWarning(ex, "Net-SNMP command failed: {Tool} {Args}", command.Tool, string.Join(" ", command.RedactedArguments));
            return new NetSnmpProcessResult(
                command.Tool,
                command.Arguments,
                command.RedactedArguments,
                ExitCode: -1,
                StandardOutput: "",
                StandardError: ex.Message,
                Duration: stopwatch.Elapsed,
                TimedOut: false,
                ErrorCode: SnmpOperationStatus.Failed);
        }
    }

    private string? ResolveTool(string tool)
    {
        if (!string.IsNullOrWhiteSpace(options.Value.ToolsPath))
        {
            var candidate = Path.Combine(options.Value.ToolsPath, OperatingSystem.IsWindows() ? tool + ".exe" : tool);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return tool;
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
        }
    }
}
