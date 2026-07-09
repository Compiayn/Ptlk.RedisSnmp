using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Services.Snmp;
using Ptlk.RedisSnmp.Services.Startup;

namespace Ptlk.RedisSnmp.Services.Trap;

public sealed class NetSnmpTrapReceiverService(
    IServiceScopeFactory scopeFactory,
    INetSnmpStreamingProcessRunner runner,
    IOptions<TrapOptions> trapOptions,
    IOptions<NetSnmpOptions> netSnmpOptions,
    RuntimeModeService runtime,
    ILogger<NetSnmpTrapReceiverService> logger) : BackgroundService
{
    private const string TrapLogFormat = "source=%b|security=%P|%V|%v\n";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!trapOptions.Value.Enabled)
        {
            runtime.SetTrap(RuntimeSubsystemStatus.Normal, "Trap receiver is disabled.");
            return;
        }

        Directory.CreateDirectory(netSnmpOptions.Value.WorkDirectory);
        var configPath = Path.Combine(netSnmpOptions.Value.WorkDirectory, "snmptrapd.conf");
        if (!File.Exists(configPath))
        {
            await File.WriteAllTextAsync(configPath, "disableAuthorization yes" + Environment.NewLine, stoppingToken);
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                runtime.SetTrap(RuntimeSubsystemStatus.Starting, $"Starting snmptrapd on UDP {trapOptions.Value.ListenPort}.");
                var trapArgs = new[] { "-f", "-Lo", "-On", "-F", TrapLogFormat, "-C", "-c", configPath, $"udp:{trapOptions.Value.ListenPort}" };
                var command = new Ptlk.RedisSnmp.Contracts.Snmp.NetSnmpCommandArguments("snmptrapd", trapArgs, trapArgs);
                var result = await runner.RunAsync(
                    command,
                    HandleTrapLineAsync,
                    HandleErrorLineAsync,
                    () => runtime.SetTrap(RuntimeSubsystemStatus.Normal, $"Listening for traps on UDP {trapOptions.Value.ListenPort}."),
                    stoppingToken);
                if (stoppingToken.IsCancellationRequested)
                {
                    return;
                }

                runtime.SetTrap(RuntimeSubsystemStatus.Degraded, result.StandardError.Length > 0 ? result.StandardError : "snmptrapd exited.");
                await Task.Delay(2000, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                runtime.SetTrap(RuntimeSubsystemStatus.Degraded, $"Trap receiver failed: {ex.Message}");
                logger.LogWarning(ex, "Trap receiver failed; retrying.");
                await Task.Delay(2000, stoppingToken);
            }
        }
    }

    private async Task HandleTrapLineAsync(string line, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return;
        }

        if (!line.TrimStart().StartsWith("source=", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogDebug("Ignoring snmptrapd stdout line: {Line}", line);
            return;
        }

        using var scope = scopeFactory.CreateScope();
        var parser = scope.ServiceProvider.GetRequiredService<TrapParser>();
        var publisher = scope.ServiceProvider.GetRequiredService<TrapEventPublisher>();
        await publisher.PublishAsync(parser.Parse(line), cancellationToken);
    }

    private Task HandleErrorLineAsync(string line, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(line))
        {
            logger.LogWarning("snmptrapd: {Line}", line);
        }

        return Task.CompletedTask;
    }
}
