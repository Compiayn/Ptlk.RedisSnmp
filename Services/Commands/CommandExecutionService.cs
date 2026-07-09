using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Redis;
using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Expressions;
using Ptlk.RedisSnmp.Services.Logs;
using Ptlk.RedisSnmp.Services.Redis;
using Ptlk.RedisSnmp.Services.Snmp;

namespace Ptlk.RedisSnmp.Services.Commands;

public sealed record CommandDispatchResult(string Status, string Message, string? CommandId);

public sealed record AcceptedWriteCommand(
    DeviceWriteCommandContract Command,
    RedisMapping Mapping,
    SnmpAgentConfig? Agent,
    SnmpPointConfig? Point,
    string RequestedPayload);

public sealed class CommandExecutionService(
    IServiceScopeFactory scopeFactory,
    RedisPubSubService pubSub,
    RedisPointOwnershipService ownership,
    IOptions<RedisSnmpOptions> redisSnmpOptions,
    ILogger<CommandExecutionService> logger)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<CommandDispatchResult> AcceptAsync(
        DeviceWriteCommandContract command,
        string requestedPayload,
        CancellationToken cancellationToken = default)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var log = scope.ServiceProvider.GetRequiredService<LogService>();
        var pointState = scope.ServiceProvider.GetRequiredService<RedisPointStateService>();
        var snmp = scope.ServiceProvider.GetRequiredService<SnmpClientService>();
        var cache = scope.ServiceProvider.GetRequiredService<SnmpValueCache>();

        var mapping = await db.RedisMappings
            .AsNoTracking()
            .FirstOrDefaultAsync(m => m.RedisKey == command.Key, cancellationToken);

        if (mapping is null)
        {
            await log.AddSystemAsync(
                "Command",
                "Info",
                $"Ignored command {command.CommandId}; no local mapping for {command.Key}.",
                command.CommandId,
                cancellationToken);
            return new CommandDispatchResult("ignored", "No local mapping.", command.CommandId);
        }

        var sourceIsSnmp = mapping.SourcePath.StartsWith("snmp:", StringComparison.OrdinalIgnoreCase);
        var sourceIsExpression = mapping.SourcePath.StartsWith("exp:", StringComparison.OrdinalIgnoreCase);
        var sourceIsRedis = mapping.SourcePath.StartsWith("rds:", StringComparison.OrdinalIgnoreCase);
        if (!sourceIsSnmp && !sourceIsExpression && !sourceIsRedis)
        {
            return await RejectAsync(command, requestedPayload, "unsupported_source", $"SourcePath '{mapping.SourcePath}' is not a writable source.", cancellationToken);
        }

        if (sourceIsSnmp && !await ownership.EnsureOwnedAsync(mapping.SourcePath, mapping.RedisKey, cancellationToken))
        {
            await log.AddSystemAsync(
                "Command",
                "Info",
                $"Ignored command {command.CommandId}; this instance does not own {mapping.SourcePath}.",
                command.CommandId,
                cancellationToken);
            return new CommandDispatchResult("ignored", "Not owned by this converter.", command.CommandId);
        }

        SnmpPointConfig? point = null;
        SnmpAgentConfig? agent = null;
        if (sourceIsSnmp)
        {
            point = await db.SnmpPointConfigs
                .AsNoTracking()
                .Include(p => p.AgentConfig)
                .ThenInclude(a => a!.CredentialConfig)
                .FirstOrDefaultAsync(p => p.SourcePath == mapping.SourcePath, cancellationToken);

            if (point?.AgentConfig is null)
            {
                return await RejectAsync(command, requestedPayload, "missing_point", $"No SNMP point exists for {mapping.SourcePath}.", cancellationToken);
            }

            if (!SnmpAccessModes.CanWrite(point.Access))
            {
                return await RejectAsync(command, requestedPayload, "set_disabled", $"SNMP access does not allow Set for {mapping.SourcePath}.", cancellationToken);
            }

            agent = point.AgentConfig;
        }

        var existing = await db.CommandExecutions
            .FirstOrDefaultAsync(c => c.CommandId == command.CommandId, cancellationToken);
        if (existing is not null)
        {
            await log.AddSystemAsync(
                "Command",
                "Info",
                $"Ignored duplicate command {command.CommandId}; current status is {existing.Status}.",
                command.CommandId,
                cancellationToken);
            return new CommandDispatchResult(existing.Status, "Duplicate commandId.", command.CommandId);
        }

        if (command.ExpectedVersion is not null)
        {
            var pointContract = await pointState.ReadAsync(mapping.RedisKey, cancellationToken);
            if (pointContract is null || pointContract.Version != command.ExpectedVersion.Value)
            {
                return await RejectAsync(
                    command,
                    requestedPayload,
                    "expected_version_mismatch",
                    $"Expected version {command.ExpectedVersion}, actual version {pointContract?.Version.ToString(CultureInfo.InvariantCulture) ?? "missing"}.",
                    cancellationToken);
            }
        }

        db.CommandExecutions.Add(new CommandExecution
        {
            CommandId = command.CommandId,
            Status = "accepted",
            RedisKey = command.Key,
            RequestedPayload = requestedPayload
        });
        await db.SaveChangesAsync(cancellationToken);

        var accepted = new AcceptedWriteCommand(command, mapping, agent, point, requestedPayload);

        if (sourceIsExpression)
        {
            var expressions = scope.ServiceProvider.GetRequiredService<ExpressionRuntimeService>();
            var expressionResult = await expressions.ExecuteWriteAsync(accepted, cancellationToken);
            if (expressionResult.Status == "failed")
            {
                return await FailAcceptedAsync(command, "expression_write_failed", expressionResult.Message, cancellationToken);
            }

            return expressionResult;
        }

        if (sourceIsRedis)
        {
            return await CompleteAsync(accepted, cancellationToken);
        }

        var snmpPoint = point ?? throw new InvalidOperationException("SNMP point was not loaded.");
        var snmpAgent = agent ?? throw new InvalidOperationException("SNMP agent was not loaded.");
        var set = await snmp.SetAsync(snmpAgent, snmpAgent.CredentialConfig, snmpPoint, command.ValueAsString(), command.CommandId, cancellationToken);
        if (!set.Success)
        {
            return await FailAcceptedAsync(command, set.ErrorCode ?? SnmpOperationStatus.Failed, set.ErrorMessage ?? "SNMP Set failed.", cancellationToken);
        }

        cache.Set(new SnmpCachedValue(
            snmpPoint.SourcePath,
            snmpAgent.AgentId,
            snmpPoint.NumericOid,
            set.Value ?? command.ValueAsString(),
            SnmpQuality.Good,
            DateTimeOffset.UtcNow,
            set.RawOutput,
            null,
            null));

        return await CompleteAsync(accepted, set.Value ?? command.ValueAsString(), cancellationToken);
    }

    public async Task<CommandDispatchResult> DirectSnmpWriteAsync(
        string sourcePath,
        string value,
        string requestedBy,
        CancellationToken cancellationToken = default)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var snmp = scope.ServiceProvider.GetRequiredService<SnmpClientService>();
        var cache = scope.ServiceProvider.GetRequiredService<SnmpValueCache>();
        var point = await db.SnmpPointConfigs
            .AsNoTracking()
            .Include(p => p.AgentConfig)
            .ThenInclude(a => a!.CredentialConfig)
            .FirstOrDefaultAsync(p => p.SourcePath == sourcePath, cancellationToken);

        if (point?.AgentConfig is null)
        {
            return new CommandDispatchResult("failed", "No SNMP point found.", null);
        }
        if (!SnmpAccessModes.CanWrite(point.Access))
        {
            return new CommandDispatchResult("failed", "SNMP access does not allow Set.", null);
        }

        var result = await snmp.SetAsync(point.AgentConfig, point.AgentConfig.CredentialConfig, point, value, null, cancellationToken);
        if (!result.Success)
        {
            return new CommandDispatchResult("failed", result.ErrorMessage ?? "SNMP Set failed.", null);
        }

        cache.Set(new SnmpCachedValue(
            point.SourcePath,
            point.AgentConfig.AgentId,
            point.NumericOid,
            result.Value ?? value,
            SnmpQuality.Good,
            DateTimeOffset.UtcNow,
            result.RawOutput,
            null,
            null));

        return new CommandDispatchResult("completed", $"Direct SNMP write completed for {requestedBy}.", null);
    }

    public async Task<CommandDispatchResult> RejectAsync(
        DeviceWriteCommandContract command,
        string requestedPayload,
        string errorCode,
        string errorMessage,
        CancellationToken cancellationToken = default)
    {
        return await FailBeforeExecutionAsync(command, requestedPayload, errorCode, errorMessage, cancellationToken);
    }

    public async Task<CommandDispatchResult> CompleteAsync(
        AcceptedWriteCommand accepted,
        string? actualValueOverride,
        CancellationToken cancellationToken = default)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var pointState = scope.ServiceProvider.GetRequiredService<RedisPointStateService>();
        var log = scope.ServiceProvider.GetRequiredService<LogService>();
        var options = redisSnmpOptions.Value;

        try
        {
            var actualValue = actualValueOverride ?? accepted.Command.ValueAsString();
            var updated = await pointState.UpdateDynamicFieldsAsync(
                accepted.Mapping,
                actualValue,
                SnmpQuality.Good,
                options.SourceName,
                cancellationToken);

            var result = new CommandResultEventContract(
                Schema: 1,
                Type: "command.completed",
                MessageId: Guid.NewGuid().ToString("N"),
                CommandId: accepted.Command.CommandId,
                Key: accepted.Mapping.RedisKey,
                Success: true,
                ActualValue: actualValueOverride is null ? accepted.Command.Value : ToJsonElement(actualValueOverride),
                Version: updated.Version,
                ErrorCode: null,
                ErrorMessage: null,
                Timestamp: DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                Source: options.SourceName);

            await UpdateExecutionAsync(db, accepted.Command.CommandId, "completed", result, null, null, cancellationToken);
            await pubSub.PublishAsync("evt:command-result", result, cancellationToken);
            await log.AddSystemAsync("Command", "Info", $"Completed command {accepted.Command.CommandId}.", accepted.Command.CommandId, cancellationToken);

            return new CommandDispatchResult("completed", "Command completed.", accepted.Command.CommandId);
        }
        catch (RedisPointUpdateException ex)
        {
            logger.LogWarning(ex, "Command {CommandId} failed during Redis output update", accepted.Command.CommandId);
            return await FailAcceptedAsync(accepted.Command, ex.Status, ex.Message, cancellationToken);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Command {CommandId} failed during Redis output update", accepted.Command.CommandId);
            return await FailAcceptedAsync(accepted.Command, "redis_output_failed", ex.Message, cancellationToken);
        }
    }

    public Task<CommandDispatchResult> CompleteAsync(
        AcceptedWriteCommand accepted,
        CancellationToken cancellationToken = default) =>
        CompleteAsync(accepted, actualValueOverride: null, cancellationToken);

    private async Task<CommandDispatchResult> FailBeforeExecutionAsync(
        DeviceWriteCommandContract command,
        string requestedPayload,
        string errorCode,
        string errorMessage,
        CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        if (!await db.CommandExecutions.AnyAsync(c => c.CommandId == command.CommandId, cancellationToken))
        {
            db.CommandExecutions.Add(new CommandExecution
            {
                CommandId = command.CommandId,
                Status = "failed",
                RedisKey = command.Key,
                RequestedPayload = requestedPayload,
                ErrorCode = errorCode,
                ErrorMessage = errorMessage
            });
            await db.SaveChangesAsync(cancellationToken);
        }

        return await PublishFailedAsync(command, errorCode, errorMessage, cancellationToken);
    }

    private async Task<CommandDispatchResult> FailAcceptedAsync(
        DeviceWriteCommandContract command,
        string errorCode,
        string errorMessage,
        CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var result = BuildFailedEvent(command, errorCode, errorMessage);
        await UpdateExecutionAsync(db, command.CommandId, "failed", result, errorCode, errorMessage, cancellationToken);
        await pubSub.PublishAsync("evt:command-result", result, cancellationToken);
        return new CommandDispatchResult("failed", errorMessage, command.CommandId);
    }

    private async Task<CommandDispatchResult> PublishFailedAsync(
        DeviceWriteCommandContract command,
        string errorCode,
        string errorMessage,
        CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var log = scope.ServiceProvider.GetRequiredService<LogService>();
        var result = BuildFailedEvent(command, errorCode, errorMessage);
        await pubSub.PublishAsync("evt:command-result", result, cancellationToken);
        await log.AddSystemAsync("Command", "Warning", errorMessage, command.CommandId, cancellationToken);
        return new CommandDispatchResult("failed", errorMessage, command.CommandId);
    }

    private CommandResultEventContract BuildFailedEvent(
        DeviceWriteCommandContract command,
        string errorCode,
        string errorMessage)
    {
        var options = redisSnmpOptions.Value;
        return new CommandResultEventContract(
            Schema: 1,
            Type: "command.failed",
            MessageId: Guid.NewGuid().ToString("N"),
            CommandId: command.CommandId,
            Key: command.Key,
            Success: false,
            ActualValue: null,
            Version: null,
            ErrorCode: errorCode,
            ErrorMessage: errorMessage,
            Timestamp: DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            Source: options.SourceName);
    }

    private static async Task UpdateExecutionAsync(
        AppDbContext db,
        string commandId,
        string status,
        CommandResultEventContract result,
        string? errorCode,
        string? errorMessage,
        CancellationToken cancellationToken)
    {
        var execution = await db.CommandExecutions.FirstAsync(c => c.CommandId == commandId, cancellationToken);
        execution.Status = status;
        execution.ResultPayload = JsonSerializer.Serialize(result, JsonOptions);
        execution.ErrorCode = errorCode;
        execution.ErrorMessage = errorMessage;
        await db.SaveChangesAsync(cancellationToken);
    }

    private static JsonElement ToJsonElement(string value)
    {
        if (bool.TryParse(value, out var boolean))
        {
            return JsonSerializer.SerializeToElement(boolean, JsonOptions);
        }

        if (double.TryParse(value, NumberStyles.Float | NumberStyles.AllowThousands, CultureInfo.InvariantCulture, out var number)
            && double.IsFinite(number))
        {
            return JsonSerializer.SerializeToElement(number, JsonOptions);
        }

        return JsonSerializer.SerializeToElement(value, JsonOptions);
    }
}
