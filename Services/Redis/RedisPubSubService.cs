using System.Text.Json;
using StackExchange.Redis;

namespace Ptlk.RedisSnmp.Services.Redis;

public interface IRedisPubSubService
{
    Task PublishAsync(string channel, object payload, CancellationToken cancellationToken = default);
}

public sealed class RedisPubSubService(
    RedisConnectionFactory redis,
    ILogger<RedisPubSubService> logger) : IRedisPubSubService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task PublishAsync(string channel, object payload, CancellationToken cancellationToken = default)
    {
        var connection = await redis.GetConnectionAsync(cancellationToken);
        var subscriber = connection.GetSubscriber();
        var json = JsonSerializer.Serialize(payload, JsonOptions);
        await subscriber.PublishAsync(RedisChannel.Literal(channel), json);
    }

    public async Task<ChannelMessageQueue> SubscribeAsync(
        string channel,
        Func<string, Task> onMessage,
        CancellationToken cancellationToken = default)
    {
        var connection = await redis.GetConnectionAsync(cancellationToken);
        var subscriber = connection.GetSubscriber();
        var queue = await subscriber.SubscribeAsync(RedisChannel.Literal(channel));
        queue.OnMessage(message =>
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    await onMessage(message.Message.ToString());
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to handle Redis message from {Channel}", channel);
                }
            }, cancellationToken);
        });

        return queue;
    }

    public async Task UnsubscribeAsync(string channel)
    {
        try
        {
            var connection = await redis.GetConnectionAsync();
            await connection.GetSubscriber().UnsubscribeAsync(RedisChannel.Literal(channel));
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to unsubscribe Redis channel {Channel}", channel);
        }
    }
}
