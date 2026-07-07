using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Services.Logs;
using Ptlk.RedisSnmp.Services.Redis;

namespace Ptlk.RedisSnmp.Services.Startup;

public sealed class StartupGateService(
    IServiceScopeFactory scopeFactory,
    RedisConnectionFactory redis,
    RuntimeModeService runtime,
    IOptions<StartupGateOptions> options,
    ILogger<StartupGateService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var deadline = DateTimeOffset.UtcNow.AddMilliseconds(options.Value.WaitInitializedTimeoutMs);
        var delay = options.Value.InitialRetryDelayMs;
        var redisOutputReadyLogged = false;
        var degradedLogged = false;
        runtime.SetRedisOutput(
            RuntimeSubsystemStatus.Starting,
            redisConnected: false,
            assetInitialized: false,
            "Waiting for Redis and Asset initialization.");

        while (!stoppingToken.IsCancellationRequested)
        {
            var redisConnected = await redis.IsConnectedAsync(stoppingToken);
            var initialized = false;
            IReadOnlyList<RedisMappingKeyCheckResult> missingMappings = [];

            if (redisConnected)
            {
                try
                {
                    var database = await redis.GetDatabaseAsync(stoppingToken);
                    initialized = (await database.StringGetAsync(".initialized")).ToString() == "1";

                    if (initialized)
                    {
                        using var scope = scopeFactory.CreateScope();
                        var validator = scope.ServiceProvider.GetRequiredService<RedisMappingValidationService>();
                        missingMappings = await validator.VerifyExistingRedisKeysAsync(stoppingToken);
                    }
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Startup gate Redis check failed");
                }
            }

            runtime.ReplaceRedisOutputDiagnostics(
                "startup_gate",
                missingMappings.Select(mapping => new RedisOutputDiagnostic(
                    mapping.SourcePath,
                    mapping.RedisKey,
                    "missing_key",
                    $"Redis point key '{mapping.RedisKey}' does not exist.",
                    "startup_gate",
                    DateTimeOffset.UtcNow)));

            if (redisConnected && initialized && missingMappings.Count == 0)
            {
                runtime.SetRedisOutput(
                    RuntimeSubsystemStatus.Normal,
                    redisConnected: true,
                    assetInitialized: true,
                    "Asset initialized and Redis output mappings are ready.");
                if (!redisOutputReadyLogged)
                {
                    await WriteLogAsync("StartupGate", "Info", "Redis output readiness is Normal.", stoppingToken);
                    redisOutputReadyLogged = true;
                }

                degradedLogged = false;
                delay = options.Value.InitialRetryDelayMs;
                await Task.Delay(1000, stoppingToken);
                continue;
            }

            var shouldDegrade = DateTimeOffset.UtcNow >= deadline
                || (redisConnected && initialized && missingMappings.Count > 0);
            if (shouldDegrade)
            {
                var reason = BuildDegradedReason(redisConnected, initialized, missingMappings);
                runtime.SetRedisOutput(
                    RuntimeSubsystemStatus.Degraded,
                    redisConnected,
                    initialized,
                    reason);
                if (!degradedLogged)
                {
                    logger.LogWarning("Redis output readiness is degraded: {Reason}", reason);
                    await WriteLogAsync("StartupGate", "Warning", reason, stoppingToken);
                    degradedLogged = true;
                }

                redisOutputReadyLogged = false;
                await Task.Delay(1000, stoppingToken);
                continue;
            }

            var message = BuildWaitingReason(redisConnected, initialized, missingMappings);
            runtime.SetRedisOutput(
                RuntimeSubsystemStatus.Starting,
                redisConnected,
                initialized,
                message);
            await Task.Delay(delay, stoppingToken);
            delay = Math.Min(delay * 2, options.Value.MaxRetryDelayMs);
        }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        runtime.Stop();
        return base.StopAsync(cancellationToken);
    }

    private async Task WriteLogAsync(string category, string level, string message, CancellationToken cancellationToken)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var log = scope.ServiceProvider.GetRequiredService<LogService>();
            await log.AddSystemAsync(category, level, message, null, cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Failed to persist startup log");
        }
    }

    private static string BuildWaitingReason(
        bool redisConnected,
        bool initialized,
        IReadOnlyList<RedisMappingKeyCheckResult> missingMappings)
    {
        if (!redisConnected)
        {
            return "Waiting for Redis connection.";
        }
        if (!initialized)
        {
            return "Waiting for Asset .initialized = 1.";
        }
        if (missingMappings.Count > 0)
        {
            return $"Checking mapped point keys: {string.Join(", ", missingMappings.Take(5).Select(m => m.RedisKey))}";
        }

        return "Waiting for startup requirements.";
    }

    private static string BuildDegradedReason(
        bool redisConnected,
        bool initialized,
        IReadOnlyList<RedisMappingKeyCheckResult> missingMappings)
    {
        if (!redisConnected)
        {
            return "Redis output degraded: Redis is not connected.";
        }
        if (!initialized)
        {
            return "Redis output degraded: Asset .initialized is not 1.";
        }
        if (missingMappings.Count > 0)
        {
            return $"Redis output degraded: missing Redis point keys: {string.Join(", ", missingMappings.Take(10).Select(m => m.RedisKey))}";
        }

        return "Redis output degraded: startup requirements were not met.";
    }
}
