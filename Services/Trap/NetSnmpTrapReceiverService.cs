using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Services.Snmp;
using Ptlk.RedisSnmp.Services.Startup;

namespace Ptlk.RedisSnmp.Services.Trap;

public sealed class NetSnmpTrapReceiverService(
    IServiceScopeFactory scopeFactory,
    INetSnmpProcessRunner runner,
    IOptions<TrapOptions> trapOptions,
    IOptions<NetSnmpOptions> netSnmpOptions,
    RuntimeModeService runtime,
    ILogger<NetSnmpTrapReceiverService> logger) : BackgroundService
{
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
                var trapArgs = new[] { "-f", "-Lo", "-On", "-C", "-c", configPath, $"udp:{trapOptions.Value.ListenPort}" };
                var command = new Ptlk.RedisSnmp.Contracts.Snmp.NetSnmpCommandArguments("snmptrapd", trapArgs, trapArgs);
                var result = await runner.RunAsync(command, Timeout.InfiniteTimeSpan, stoppingToken);
                if (stoppingToken.IsCancellationRequested)
                {
                    return;
                }

                if (!string.IsNullOrWhiteSpace(result.StandardOutput))
                {
                    using var scope = scopeFactory.CreateScope();
                    var parser = scope.ServiceProvider.GetRequiredService<TrapParser>();
                    var publisher = scope.ServiceProvider.GetRequiredService<TrapEventPublisher>();
                    await publisher.PublishAsync(parser.Parse(result.StandardOutput), stoppingToken);
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
}
