using Ptlk.RedisSnmp.Services.Redis;
using Ptlk.RedisSnmp.Services.Startup;

namespace Ptlk.RedisSnmp.Services.Commands;

public sealed class DeviceCommandSubscriptionService(
    IServiceScopeFactory scopeFactory,
    RuntimeModeService runtime,
    RedisPubSubService pubSub,
    ILogger<DeviceCommandSubscriptionService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            if (!runtime.Current.RedisConnected)
            {
                await Task.Delay(1000, stoppingToken);
                continue;
            }

            const string channel = "cmd:device-write";
            try
            {
                await pubSub.SubscribeAsync(channel, DispatchAsync, stoppingToken);
                logger.LogInformation("Subscribed Redis command channel {Channel}", channel);
                await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Command subscription failed; retrying");
                await Task.Delay(2000, stoppingToken);
            }
            finally
            {
                await pubSub.UnsubscribeAsync(channel);
            }
        }
    }

    private async Task DispatchAsync(string payload)
    {
        using var scope = scopeFactory.CreateScope();
        var dispatcher = scope.ServiceProvider.GetRequiredService<CommandDispatcherService>();
        await dispatcher.DispatchRawAsync(payload);
    }
}
