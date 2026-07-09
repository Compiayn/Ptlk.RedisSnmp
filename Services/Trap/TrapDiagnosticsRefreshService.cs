namespace Ptlk.RedisSnmp.Services.Trap;

public sealed record TrapDiagnosticsChanged(int DiagnosticId, DateTimeOffset ChangedAt);

public sealed class TrapDiagnosticsRefreshService(ILogger<TrapDiagnosticsRefreshService> logger)
{
    private static readonly TimeSpan DispatchCoalesceDelay = TimeSpan.FromMilliseconds(100);
    private readonly object sync = new();
    private readonly Dictionary<Guid, Action<TrapDiagnosticsChanged>> subscribers = new();
    private TrapDiagnosticsChanged? pendingNotification;
    private bool dispatchScheduled;

    public IDisposable Subscribe(Action<TrapDiagnosticsChanged> handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        var id = Guid.NewGuid();
        lock (sync)
        {
            subscribers[id] = handler;
        }

        return new Subscription(() => Unsubscribe(id));
    }

    public void NotifyDiagnosticRecorded(int diagnosticId)
    {
        lock (sync)
        {
            pendingNotification = new TrapDiagnosticsChanged(diagnosticId, DateTimeOffset.UtcNow);
            if (dispatchScheduled)
            {
                return;
            }

            dispatchScheduled = true;
        }

        _ = Task.Run(DispatchPendingAsync);
    }

    private async Task DispatchPendingAsync()
    {
        while (true)
        {
            await Task.Delay(DispatchCoalesceDelay);

            TrapDiagnosticsChanged? changed;
            Action<TrapDiagnosticsChanged>[] snapshot;
            lock (sync)
            {
                changed = pendingNotification;
                pendingNotification = null;
                snapshot = subscribers.Values.ToArray();
            }

            if (changed is not null && snapshot.Length > 0)
            {
                Dispatch(changed, snapshot);
            }

            lock (sync)
            {
                if (pendingNotification is null)
                {
                    dispatchScheduled = false;
                    return;
                }
            }
        }
    }

    private void Dispatch(TrapDiagnosticsChanged changed, IReadOnlyList<Action<TrapDiagnosticsChanged>> snapshot)
    {
        foreach (var subscriber in snapshot)
        {
            try
            {
                subscriber(changed);
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Trap diagnostics refresh subscriber failed.");
            }
        }
    }

    private void Unsubscribe(Guid id)
    {
        lock (sync)
        {
            subscribers.Remove(id);
        }
    }

    private sealed class Subscription(Action unsubscribe) : IDisposable
    {
        private Action? unsubscribe = unsubscribe;

        public void Dispose()
        {
            Interlocked.Exchange(ref unsubscribe, null)?.Invoke();
        }
    }
}
