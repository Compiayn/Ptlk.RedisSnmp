using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Redis;
using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Commands;
using Ptlk.RedisSnmp.Services.Logs;
using Ptlk.RedisSnmp.Services.Redis;
using Ptlk.RedisSnmp.Services.Snmp;

namespace Ptlk.RedisSnmp.Services.Expressions;

public sealed record ExpressionEvaluationResult(
    string SourcePath,
    string? RedisKey,
    string? Value,
    string Quality,
    string? Error);

public sealed class ExpressionRuntimeService(
    AppDbContext db,
    ExpressionScriptEngine engine,
    RedisPointStateService pointState,
    CommandDispatcherService dispatcher,
    CommandExecutionService commands,
    LogService log,
    SnmpValueCache snmpCache,
    ExpressionValueCache expressionCache,
    IOptions<RedisSnmpOptions> redisSnmpOptions)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<IReadOnlyList<ExpressionEvaluationResult>> EvaluateReadableExpressionsAsync(
        CancellationToken cancellationToken = default)
    {
        var expressions = await db.ExpressionConfigs
            .AsNoTracking()
            .Include(e => e.Bindings)
            .Where(e => e.Rw == "Ro" || e.Rw == "Rw")
            .OrderBy(e => e.Name)
            .ToListAsync(cancellationToken);

        var mappings = await db.RedisMappings
            .AsNoTracking()
            .ToDictionaryAsync(m => m.SourcePath, StringComparer.OrdinalIgnoreCase, cancellationToken);

        var results = new List<ExpressionEvaluationResult>();
        foreach (var expression in expressions)
        {
            results.Add(await EvaluateReadableExpressionAsync(expression, mappings, cancellationToken));
        }

        return results;
    }

    public async Task<ExpressionEvaluationResult> EvaluateReadableExpressionAsync(
        ExpressionConfig expression,
        IReadOnlyDictionary<string, RedisMapping> mappings,
        CancellationToken cancellationToken = default)
    {
        var sourcePath = ExpressionService.SourcePathFor(expression.Name);
        mappings.TryGetValue(sourcePath, out var targetMapping);

        try
        {
            var bindingValues = await ReadBindingValuesAsync(expression.Bindings, mappings, cancellationToken);
            var missingBinding = bindingValues.FirstOrDefault(v => v.Missing);
            if (missingBinding is not null)
            {
                var message = $"Binding '{missingBinding.ParameterName}' has no readable value. {missingBinding.MissingReason}";
                expressionCache.Set(sourcePath, null, SnmpQuality.Bad, message);
                await TryUpdateRedisExpressionPointIfMappedAsync(
                    sourcePath,
                    targetMapping,
                    null,
                    SnmpQuality.Bad,
                    cancellationToken);
                return new ExpressionEvaluationResult(
                    sourcePath,
                    targetMapping?.RedisKey,
                    null,
                    SnmpQuality.Bad,
                    message);
            }

            var worstQuality = WorstQuality(bindingValues.Select(v => v.Quality));
            var variables = bindingValues.ToDictionary(v => v.ParameterName, v => v.Value, StringComparer.Ordinal);
            var result = engine.Execute(expression.ReadScript ?? "", variables, cancellationToken);
            var returnName = expression.ReadReturnParameter ?? "";
            if (!result.Variables.TryGetValue(returnName, out var returnValue))
            {
                throw new InvalidOperationException($"Read return parameter '{returnName}' was not assigned.");
            }

            var value = ExpressionValueTypes.ToPointValue(returnValue, expression.ValueType);
            expressionCache.Set(sourcePath, value, worstQuality);
            await TryUpdateRedisExpressionPointIfMappedAsync(
                sourcePath,
                targetMapping,
                value,
                worstQuality,
                cancellationToken);
            return new ExpressionEvaluationResult(sourcePath, targetMapping?.RedisKey, value, worstQuality, null);
        }
        catch (Exception ex)
        {
            await log.AddSystemAsync("Expression", "Warning", $"{sourcePath} read failed: {ex.Message}", null, cancellationToken);
            expressionCache.Set(sourcePath, null, SnmpQuality.Bad, ex.Message);
            await TryUpdateRedisExpressionPointIfMappedAsync(
                sourcePath,
                targetMapping,
                null,
                SnmpQuality.Bad,
                cancellationToken);

            return new ExpressionEvaluationResult(sourcePath, targetMapping?.RedisKey, null, SnmpQuality.Bad, ex.Message);
        }
    }

    public async Task<CommandDispatchResult> ExecuteWriteAsync(
        AcceptedWriteCommand accepted,
        CancellationToken cancellationToken = default)
    {
        var expressionName = accepted.Mapping.SourcePath[4..];
        var expression = await db.ExpressionConfigs
            .AsNoTracking()
            .Include(e => e.Bindings)
            .FirstOrDefaultAsync(e => e.Name == expressionName, cancellationToken);

        if (expression is null)
        {
            return new CommandDispatchResult("failed", $"Expression '{expressionName}' was not found.", accepted.Command.CommandId);
        }

        if (expression.Rw == "Ro")
        {
            return new CommandDispatchResult("failed", $"{accepted.Mapping.SourcePath} is read-only.", accepted.Command.CommandId);
        }

        try
        {
            var mappings = await db.RedisMappings
                .AsNoTracking()
                .ToDictionaryAsync(m => m.SourcePath, StringComparer.OrdinalIgnoreCase, cancellationToken);
            var bindingValues = await ReadBindingValuesAsync(expression.Bindings, mappings, cancellationToken);
            var variables = bindingValues.ToDictionary(v => v.ParameterName, v => v.Value, StringComparer.Ordinal);
            if (!string.IsNullOrWhiteSpace(expression.WriteInputParameter))
            {
                variables[expression.WriteInputParameter] = ExpressionValueTypes.ConvertFromPointValue(
                    accepted.Command.ValueAsString(),
                    expression.ValueType,
                    expression.WriteInputParameter);
            }

            var result = engine.Execute(expression.WriteScript ?? "", variables, cancellationToken);
            var writes = expression.Bindings
                .Where(b => result.AssignedVariables.Contains(b.ParameterName))
                .ToList();

            if (writes.Count == 0)
            {
                return new CommandDispatchResult("failed", "Write script did not assign any binding parameter.", accepted.Command.CommandId);
            }

            foreach (var binding in writes)
            {
                if (!mappings.TryGetValue(binding.SourcePath, out var targetMapping))
                {
                    throw new InvalidOperationException($"Binding source '{binding.SourcePath}' has no Redis mapping.");
                }

                if (!targetMapping.SourcePath.StartsWith("snmp:", StringComparison.OrdinalIgnoreCase)
                    && !targetMapping.SourcePath.StartsWith("rds:", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException($"Binding source '{binding.SourcePath}' is not a writable target.");
                }

                var targetPoint = await pointState.ReadAsync(targetMapping.RedisKey, cancellationToken);
                var targetValueType = await ResolveBindingValueTypeAsync(binding.SourcePath, targetPoint, cancellationToken);
                var child = new DeviceWriteCommandContract
                {
                    CommandId = $"{accepted.Command.CommandId}:{binding.ParameterName}",
                    Key = targetMapping.RedisKey,
                    Value = JsonSerializer.SerializeToElement(
                        ExpressionValueTypes.ToPointValue(result.Variables[binding.ParameterName], targetValueType),
                        JsonOptions),
                    RequestedBy = accepted.Command.RequestedBy,
                    Source = redisSnmpOptions.Value.SourceName,
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                };
                var payload = JsonSerializer.Serialize(child, JsonOptions);
                var childResult = await dispatcher.DispatchAsync(child, payload, cancellationToken);
                if (childResult.Status is "failed")
                {
                    throw new InvalidOperationException($"Binding write '{binding.ParameterName}' failed: {childResult.Message}");
                }
            }

            var completed = await commands.CompleteAsync(accepted, cancellationToken);

            await log.AddSystemAsync("Expression", "Info", $"Executed write expression {accepted.Mapping.SourcePath}.", accepted.Command.CommandId, cancellationToken);
            return new CommandDispatchResult("completed", completed.Message, accepted.Command.CommandId);
        }
        catch (Exception ex)
        {
            await log.AddSystemAsync("Expression", "Warning", $"{accepted.Mapping.SourcePath} write failed: {ex.Message}", accepted.Command.CommandId, cancellationToken);
            return new CommandDispatchResult("failed", ex.Message, accepted.Command.CommandId);
        }
    }

    private async Task<IReadOnlyList<BindingRuntimeValue>> ReadBindingValuesAsync(
        IReadOnlyList<ExpressionBinding> bindings,
        IReadOnlyDictionary<string, RedisMapping> mappings,
        CancellationToken cancellationToken)
    {
        var result = new List<BindingRuntimeValue>();
        foreach (var binding in bindings)
        {
            if (binding.SourcePath.StartsWith("snmp:", StringComparison.OrdinalIgnoreCase))
            {
                var point = await db.SnmpPointConfigs
                    .AsNoTracking()
                    .FirstOrDefaultAsync(t => t.SourcePath == binding.SourcePath, cancellationToken);
                if (point is null)
                {
                    result.Add(new BindingRuntimeValue(
                        binding.ParameterName,
                        null,
                        SnmpQuality.Bad,
                        ExpressionValueTypes.Double,
                        Missing: true,
                        MissingReason: $"SNMP binding source '{binding.SourcePath}' has no SnmpPointConfig."));
                    continue;
                }

                var valueType = ExpressionValueTypes.FromSnmpValueType(point.ValueType);
                var cached = snmpCache.Get(binding.SourcePath);
                var missingSnmpValue = cached is null || string.IsNullOrWhiteSpace(cached.Value);
                result.Add(new BindingRuntimeValue(
                    binding.ParameterName,
                    missingSnmpValue ? null : ExpressionValueTypes.ConvertFromPointValue(cached?.Value, valueType, binding.ParameterName),
                    cached?.Quality ?? SnmpQuality.Bad,
                    valueType,
                    missingSnmpValue,
                    MissingReason: missingSnmpValue ? $"SNMP binding source '{binding.SourcePath}' has not been polled yet." : null));
                continue;
            }

            if (binding.SourcePath.StartsWith("exp:", StringComparison.OrdinalIgnoreCase))
            {
                var cachedExpression = expressionCache.Get(binding.SourcePath);
                var expressionValueType = await ResolveBindingValueTypeAsync(binding.SourcePath, null, cancellationToken);
                var missingExpressionValue = cachedExpression is null || string.IsNullOrWhiteSpace(cachedExpression.Value);
                result.Add(new BindingRuntimeValue(
                    binding.ParameterName,
                    missingExpressionValue
                        ? null
                        : ExpressionValueTypes.ConvertFromPointValue(
                            cachedExpression?.Value,
                            expressionValueType,
                            binding.ParameterName),
                    cachedExpression?.Quality ?? SnmpQuality.Bad,
                    expressionValueType,
                    missingExpressionValue,
                    MissingReason: missingExpressionValue
                        ? cachedExpression?.Error ?? $"Expression binding source '{binding.SourcePath}' has not been evaluated yet."
                        : null));
                continue;
            }

            if (!mappings.TryGetValue(binding.SourcePath, out var mapping))
            {
                result.Add(new BindingRuntimeValue(
                    binding.ParameterName,
                    null,
                    SnmpQuality.Bad,
                    ExpressionValueTypes.Double,
                    Missing: true,
                    MissingReason: $"Binding source '{binding.SourcePath}' has no Redis mapping."));
                continue;
            }

            var redisPoint = await pointState.ReadAsync(mapping.RedisKey, cancellationToken);
            var redisValueType = await ResolveBindingValueTypeAsync(binding.SourcePath, redisPoint, cancellationToken);
            var missing = redisPoint is null || string.IsNullOrWhiteSpace(redisPoint.Value);
            var value = missing
                ? null
                : ExpressionValueTypes.ConvertFromPointValue(redisPoint?.Value, redisValueType, binding.ParameterName);
            result.Add(new BindingRuntimeValue(
                binding.ParameterName,
                value,
                redisPoint?.Quality ?? SnmpQuality.Bad,
                redisValueType,
                missing,
                MissingReason: missing ? $"Binding source '{binding.SourcePath}' has no readable value." : null));
        }

        return result;
    }

    private async Task<string> ResolveBindingValueTypeAsync(
        string sourcePath,
        PointStateContract? point,
        CancellationToken cancellationToken)
    {
        if (sourcePath.StartsWith("snmp:", StringComparison.OrdinalIgnoreCase))
        {
            var snmpPoint = await db.SnmpPointConfigs
                .AsNoTracking()
                .FirstOrDefaultAsync(t => t.SourcePath == sourcePath, cancellationToken);
            if (snmpPoint is null)
            {
                throw new InvalidOperationException($"SNMP binding source '{sourcePath}' has no SnmpPointConfig.");
            }

            return ExpressionValueTypes.FromSnmpValueType(snmpPoint.ValueType);
        }

        if (sourcePath.StartsWith("exp:", StringComparison.OrdinalIgnoreCase))
        {
            var expressionName = sourcePath[4..];
            var expression = await db.ExpressionConfigs
                .AsNoTracking()
                .FirstOrDefaultAsync(e => e.Name == expressionName, cancellationToken);
            if (expression is null)
            {
                throw new InvalidOperationException($"Expression binding source '{sourcePath}' has no ExpressionConfig.");
            }

            return ExpressionValueTypes.Normalize(expression.ValueType);
        }

        return ExpressionValueTypes.FromRedisPointType(point?.Type);
    }

    private sealed record BindingRuntimeValue(
        string ParameterName,
        object? Value,
        string Quality,
        string ValueType,
        bool Missing,
        string? MissingReason = null);

    private static string WorstQuality(IEnumerable<string> qualities)
    {
        var result = SnmpQuality.Good;
        foreach (var quality in qualities)
        {
            if (quality.Equals(SnmpQuality.Bad, StringComparison.OrdinalIgnoreCase))
            {
                return SnmpQuality.Bad;
            }

            if (!quality.Equals(SnmpQuality.Good, StringComparison.OrdinalIgnoreCase))
            {
                result = SnmpQuality.Unset;
            }
        }

        return result;
    }

    private async Task TryUpdateRedisExpressionPointIfMappedAsync(
        string sourcePath,
        RedisMapping? mapping,
        string? value,
        string quality,
        CancellationToken cancellationToken)
    {
        if (mapping is null)
        {
            return;
        }

        try
        {
            await pointState.UpdateDynamicFieldsAsync(
                mapping,
                value,
                quality,
                redisSnmpOptions.Value.SourceName,
                cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            await log.AddSystemAsync(
                "Expression",
                "Warning",
                $"{sourcePath} Redis output update failed for {mapping.RedisKey}: {ex.Message}",
                null,
                cancellationToken);
        }
    }
}
