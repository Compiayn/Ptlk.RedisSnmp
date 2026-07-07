using System.Text.Json;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Redis;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Logs;

namespace Ptlk.RedisSnmp.Services.Commands;

public sealed class CommandDispatcherService(
    CommandExecutionService execution,
    LogService log,
    IOptions<RedisSnmpOptions> redisSnmpOptions)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<CommandDispatchResult> DispatchRawAsync(
        string payload,
        CancellationToken cancellationToken = default)
    {
        DeviceWriteCommandContract? command;
        try
        {
            command = JsonSerializer.Deserialize<DeviceWriteCommandContract>(payload, JsonOptions);
        }
        catch (JsonException ex)
        {
            await log.AddSystemAsync("Command", "Warning", $"Invalid command JSON: {ex.Message}", null, cancellationToken);
            return new CommandDispatchResult("failed", "Invalid JSON.", null);
        }

        if (command is null)
        {
            await log.AddSystemAsync("Command", "Warning", "Invalid command payload: empty body.", null, cancellationToken);
            return new CommandDispatchResult("failed", "Empty command.", null);
        }

        return await DispatchAsync(command, payload, cancellationToken);
    }

    public async Task<CommandDispatchResult> DispatchAsync(
        DeviceWriteCommandContract command,
        string requestedPayload,
        CancellationToken cancellationToken = default)
    {
        var validation = Validate(command);
        if (validation is not null)
        {
            if (string.IsNullOrWhiteSpace(command.CommandId))
            {
                await log.AddSystemAsync("Command", "Warning", validation, command.CommandId, cancellationToken);
                return new CommandDispatchResult("failed", validation, command.CommandId);
            }

            return await execution.RejectAsync(command, requestedPayload, "invalid_payload", validation, cancellationToken);
        }

        return await execution.AcceptAsync(command, requestedPayload, cancellationToken);
    }

    public Task<CommandDispatchResult> DispatchHmiWriteAsync(
        RedisMapping mapping,
        string value,
        string requestedBy,
        CancellationToken cancellationToken = default)
    {
        var options = redisSnmpOptions.Value;
        var command = new DeviceWriteCommandContract
        {
            CommandId = Guid.NewGuid().ToString("N"),
            Key = mapping.RedisKey,
            Value = JsonSerializer.SerializeToElement(value, JsonOptions),
            RequestedBy = requestedBy,
            Source = options.SourceName,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
        };
        var payload = JsonSerializer.Serialize(command, JsonOptions);
        return DispatchAsync(command, payload, cancellationToken);
    }

    private static string? Validate(DeviceWriteCommandContract command)
    {
        if (string.IsNullOrWhiteSpace(command.CommandId))
        {
            return "commandId is required.";
        }
        if (string.IsNullOrWhiteSpace(command.Key))
        {
            return "key is required.";
        }
        if (!command.Key.StartsWith("point:", StringComparison.OrdinalIgnoreCase))
        {
            return "key must start with point:.";
        }
        if (command.Value.ValueKind == JsonValueKind.Undefined)
        {
            return "value is required.";
        }

        return null;
    }
}
