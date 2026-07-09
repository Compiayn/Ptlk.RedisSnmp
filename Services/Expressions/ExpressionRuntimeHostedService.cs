namespace Ptlk.RedisSnmp.Services.Expressions;

public sealed class ExpressionRuntimeHostedService(
    IServiceScopeFactory scopeFactory,
    ILogger<ExpressionRuntimeHostedService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var expressions = scope.ServiceProvider.GetRequiredService<ExpressionRuntimeService>();
                await expressions.EvaluateReadableExpressionsAsync(stoppingToken);
                await Task.Delay(1000, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Expression runtime loop failed");
                await Task.Delay(1000, stoppingToken);
            }
        }
    }
}
