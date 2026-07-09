using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Snmp;

namespace Ptlk.RedisSnmp.Services.Snmp;

public interface INetSnmpStreamingProcessRunner
{
    Task<NetSnmpProcessResult> RunAsync(
        NetSnmpCommandArguments command,
        Func<string, CancellationToken, Task> onStandardOutputLine,
        Func<string, CancellationToken, Task>? onStandardErrorLine = null,
        Action? onStarted = null,
        CancellationToken cancellationToken = default);
}

public sealed class NetSnmpStreamingProcessRunner(
    IOptions<NetSnmpOptions> options,
    ILogger<NetSnmpStreamingProcessRunner> logger) : INetSnmpStreamingProcessRunner
{
    public async Task<NetSnmpProcessResult> RunAsync(
        NetSnmpCommandArguments command,
        Func<string, CancellationToken, Task> onStandardOutputLine,
        Func<string, CancellationToken, Task>? onStandardErrorLine = null,
        Action? onStarted = null,
        CancellationToken cancellationToken = default)
    {
        var toolPath = ResolveTool(command.Tool);
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        var stopwatch = Stopwatch.StartNew();

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
            onStarted?.Invoke();

            var stdoutTask = ReadLinesAsync(
                process.StandardOutput,
                stdout,
                onStandardOutputLine,
                "stdout",
                cancellationToken);
            var stderrTask = ReadLinesAsync(
                process.StandardError,
                stderr,
                onStandardErrorLine,
                "stderr",
                cancellationToken);

            await process.WaitForExitAsync(cancellationToken);
            await Task.WhenAll(stdoutTask, stderrTask);
            stopwatch.Stop();

            return new NetSnmpProcessResult(
                command.Tool,
                command.Arguments,
                command.RedactedArguments,
                process.ExitCode,
                stdout.ToString(),
                stderr.ToString(),
                stopwatch.Elapsed,
                TimedOut: false,
                ErrorCode: process.ExitCode == 0 ? null : SnmpOperationStatus.Failed);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            stopwatch.Stop();
            TryKill(process);
            throw;
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            TryKill(process);
            logger.LogWarning(ex, "Net-SNMP streaming command failed: {Tool} {Args}", command.Tool, string.Join(" ", command.RedactedArguments));
            return new NetSnmpProcessResult(
                command.Tool,
                command.Arguments,
                command.RedactedArguments,
                ExitCode: -1,
                StandardOutput: stdout.ToString(),
                StandardError: string.IsNullOrWhiteSpace(stderr.ToString()) ? ex.Message : stderr.ToString(),
                Duration: stopwatch.Elapsed,
                TimedOut: false,
                ErrorCode: SnmpOperationStatus.Failed);
        }
    }

    private async Task ReadLinesAsync(
        StreamReader reader,
        StringBuilder capture,
        Func<string, CancellationToken, Task>? onLine,
        string streamName,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null)
            {
                return;
            }

            capture.AppendLine(line);
            if (onLine is null || string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            try
            {
                await onLine(line, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Net-SNMP {StreamName} line handler failed.", streamName);
            }
        }
    }

    private string ResolveTool(string tool)
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
