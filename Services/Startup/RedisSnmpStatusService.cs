using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Redis;
using Ptlk.RedisSnmp.Services.Redis;

namespace Ptlk.RedisSnmp.Services.Startup;

public sealed class RedisSnmpStatusService(
    RuntimeModeService runtime,
    RedisPubSubService pubSub,
    RedisPointOwnershipService ownership,
    IOptions<RedisSnmpOptions> redisSnmpOptions,
    IOptions<RedisSnmpRuntimeOptions> runtimeOptions,
    ILogger<RedisSnmpStatusService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await PublishAsync("RedisProtocolConverter.online", "online", stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(runtimeOptions.Value.HeartbeatIntervalMs, stoppingToken);
                await PublishAsync("RedisProtocolConverter.heartbeat", "heartbeat", stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Failed to publish RedisSnmp heartbeat");
            }
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await PublishAsync("RedisProtocolConverter.offline", "offline", cancellationToken);
        await base.StopAsync(cancellationToken);
    }

    private async Task PublishAsync(string type, string status, CancellationToken cancellationToken)
    {
        try
        {
            var options = redisSnmpOptions.Value;
            var current = runtime.Current;
            var claims = ownership.Snapshot();
            var evt = new RedisProtocolConverterStatusEventContract(
                Schema: 1,
                Type: type,
                MessageId: Guid.NewGuid().ToString("N"),
                ConverterId: options.ConverterId,
                Status: status,
                Timestamp: DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Source: options.SourceName,
                Metadata: new Dictionary<string, string?>
                {
                    ["mode"] = current.Mode.ToString(),
                    ["message"] = current.Message,
                    ["acquisitionStatus"] = current.AcquisitionStatus.ToString(),
                    ["acquisitionMessage"] = current.AcquisitionMessage,
                    ["redisOutputStatus"] = current.RedisOutputStatus.ToString(),
                    ["redisOutputMessage"] = current.RedisOutputMessage,
                    ["trapStatus"] = current.TrapStatus.ToString(),
                    ["trapMessage"] = current.TrapMessage,
                    ["mibStatus"] = current.MibStatus.ToString(),
                    ["mibMessage"] = current.MibMessage,
                    ["redisConnected"] = current.RedisConnected ? "true" : "false",
                    ["assetInitialized"] = current.AssetInitialized ? "true" : "false",
                    ["redisOutputDiagnosticsCount"] = current.RedisOutputDiagnostics.Count.ToString(),
                    ["ownershipClaims"] = claims.Count.ToString(),
                    ["ownershipAcquired"] = claims.Count(item => item.Acquired).ToString()
                });

            await pubSub.PublishAsync("evt:edge-status", evt, cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Failed to publish RedisSnmp status {Status}", status);
        }
    }
}
