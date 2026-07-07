using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Redis;
using Ptlk.RedisSnmp.Services.Startup;

namespace Ptlk.RedisSnmp.Services.Snmp;

public sealed class SnmpPollingHostedService(
    IServiceScopeFactory scopeFactory,
    SnmpValueCache cache,
    SnmpQualityPolicy quality,
    RedisPointOwnershipService ownership,
    RuntimeModeService runtime,
    IOptions<RedisSnmpOptions> options,
    IOptions<SnmpRuntimeOptions> runtimeOptions,
    ILogger<SnmpPollingHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        runtime.SetAcquisition(RuntimeSubsystemStatus.Starting, "Starting SNMP polling.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var snmp = scope.ServiceProvider.GetRequiredService<SnmpClientService>();
                var pointState = scope.ServiceProvider.GetRequiredService<RedisPointStateService>();

                var agents = await db.SnmpAgentConfigs
                    .AsNoTracking()
                    .Include(a => a.CredentialConfig)
                    .Include(a => a.Points.Where(p => p.PollEnabled))
                    .Where(a => a.Enabled)
                    .OrderBy(a => a.AgentId)
                    .ToListAsync(stoppingToken);

                if (agents.Count == 0)
                {
                    runtime.SetAcquisition(RuntimeSubsystemStatus.Normal, "No enabled SNMP agents configured.");
                    await Task.Delay(runtimeOptions.Value.DefaultPollingRateMs, stoppingToken);
                    continue;
                }

                runtime.SetAcquisition(RuntimeSubsystemStatus.Normal, $"Polling {agents.Count} SNMP agent(s).");
                foreach (var agent in agents)
                {
                    await PollAgentAsync(db, snmp, pointState, agent, stoppingToken);
                }

                var delay = agents.Count == 0
                    ? runtimeOptions.Value.DefaultPollingRateMs
                    : Math.Max(100, agents.Min(a => a.PollingRateMs > 0 ? a.PollingRateMs : runtimeOptions.Value.DefaultPollingRateMs));
                await Task.Delay(delay, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                runtime.SetAcquisition(RuntimeSubsystemStatus.Degraded, $"SNMP polling failed: {ex.Message}");
                logger.LogWarning(ex, "SNMP polling loop failed.");
                await Task.Delay(1000, stoppingToken);
            }
        }
    }

    private async Task PollAgentAsync(
        AppDbContext db,
        SnmpClientService snmp,
        RedisPointStateService pointState,
        SnmpAgentConfig agent,
        CancellationToken cancellationToken)
    {
        var points = agent.Points.Where(p => p.PollEnabled).OrderBy(p => p.NumericOid).ToList();
        foreach (var point in points)
        {
            var get = await snmp.GetAsync(agent, agent.CredentialConfig, point.NumericOid, cancellationToken);
            if (quality.IsAgentLevelFailure(get))
            {
                cache.MarkAgentBad(
                    agent.AgentId,
                    points.Select(p => (p.SourcePath, p.NumericOid)),
                    get.ErrorCode ?? SnmpOperationStatus.Failed,
                    get.ErrorMessage ?? "Agent-level SNMP failure.");

                await WriteAgentBadToRedisAsync(db, pointState, points, get, cancellationToken);
                return;
            }

            var result = quality.FromGetResult(point, get);
            cache.Set(new SnmpCachedValue(
                point.SourcePath,
                agent.AgentId,
                point.NumericOid,
                result.Value,
                result.Quality,
                DateTimeOffset.UtcNow,
                result.RawValue,
                result.ErrorCode,
                result.ErrorMessage));

            await WritePointToRedisAsync(db, pointState, point.SourcePath, result.Value, result.Quality, cancellationToken);
        }
    }

    private async Task WriteAgentBadToRedisAsync(
        AppDbContext db,
        RedisPointStateService pointState,
        IReadOnlyList<SnmpPointConfig> points,
        SnmpGetResult failure,
        CancellationToken cancellationToken)
    {
        foreach (var point in points)
        {
            await WritePointToRedisAsync(db, pointState, point.SourcePath, null, SnmpQuality.Bad, cancellationToken);
        }
    }

    private async Task WritePointToRedisAsync(
        AppDbContext db,
        RedisPointStateService pointState,
        string sourcePath,
        string? value,
        string qualityValue,
        CancellationToken cancellationToken)
    {
        if (!runtime.Current.RedisConnected || !runtime.Current.AssetInitialized)
        {
            return;
        }

        var mapping = await db.RedisMappings.AsNoTracking().FirstOrDefaultAsync(m => m.SourcePath == sourcePath, cancellationToken);
        if (mapping is null)
        {
            return;
        }

        if (!await ownership.EnsureOwnedAsync(mapping.SourcePath, mapping.RedisKey, cancellationToken))
        {
            return;
        }

        try
        {
            await pointState.UpdateDynamicFieldsAsync(mapping, value, qualityValue, options.Value.SourceName, cancellationToken);
        }
        catch (RedisPointUpdateException ex)
        {
            logger.LogDebug(ex, "Redis output update failed for {SourcePath}.", mapping.SourcePath);
        }
    }
}
