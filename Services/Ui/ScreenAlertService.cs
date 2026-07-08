namespace Ptlk.RedisSnmp.Services.Ui;

public enum ScreenAlertSeverity
{
    Info,
    Success,
    Warning,
    Error
}

public sealed record ScreenAlertMessage(
    Guid Id,
    ScreenAlertSeverity Severity,
    string Message,
    string? Title,
    TimeSpan Duration,
    DateTimeOffset CreatedAt);

public sealed class ScreenAlertService
{
    private static readonly TimeSpan MinimumDuration = TimeSpan.FromSeconds(3);
    private readonly object sync = new();
    private readonly Queue<ScreenAlertMessage> pending = new();

    public event Action? AlertsChanged;

    public Task ShowAsync(
        string message,
        ScreenAlertSeverity severity = ScreenAlertSeverity.Info,
        string? title = null,
        TimeSpan? duration = null)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return Task.CompletedTask;
        }

        var alert = new ScreenAlertMessage(
            Guid.NewGuid(),
            severity,
            message.Trim(),
            string.IsNullOrWhiteSpace(title) ? null : title.Trim(),
            NormalizeDuration(duration),
            DateTimeOffset.Now);

        lock (sync)
        {
            pending.Enqueue(alert);
        }

        AlertsChanged?.Invoke();
        return Task.CompletedTask;
    }

    public IReadOnlyList<ScreenAlertMessage> Drain()
    {
        lock (sync)
        {
            if (pending.Count == 0)
            {
                return [];
            }

            var alerts = pending.ToArray();
            pending.Clear();
            return alerts;
        }
    }

    private static TimeSpan NormalizeDuration(TimeSpan? duration) =>
        duration is null || duration.Value < MinimumDuration ? MinimumDuration : duration.Value;
}
