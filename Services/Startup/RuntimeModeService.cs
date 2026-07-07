namespace Ptlk.RedisSnmp.Services.Startup;

public enum RuntimeMode
{
    Starting,
    Normal,
    Degraded,
    Stopping
}

public enum RuntimeSubsystemStatus
{
    Starting,
    Normal,
    Degraded,
    Stopping
}

public sealed record RedisOutputDiagnostic(
    string SourcePath,
    string RedisKey,
    string Status,
    string Message,
    string Origin,
    DateTimeOffset UpdatedAt);

public sealed record RuntimeState(
    RuntimeMode Mode,
    bool RedisConnected,
    bool AssetInitialized,
    string Message,
    DateTimeOffset UpdatedAt,
    RuntimeSubsystemStatus AcquisitionStatus,
    string AcquisitionMessage,
    RuntimeSubsystemStatus RedisOutputStatus,
    string RedisOutputMessage,
    RuntimeSubsystemStatus TrapStatus,
    string TrapMessage,
    RuntimeSubsystemStatus MibStatus,
    string MibMessage,
    IReadOnlyList<RedisOutputDiagnostic> RedisOutputDiagnostics);

public sealed class RuntimeModeService
{
    private readonly object _sync = new();
    private readonly Dictionary<string, RedisOutputDiagnostic> _redisOutputDiagnostics = new(StringComparer.OrdinalIgnoreCase);
    private bool _redisConnected;
    private bool _assetInitialized;
    private RuntimeSubsystemStatus _acquisitionStatus = RuntimeSubsystemStatus.Starting;
    private RuntimeSubsystemStatus _redisOutputBaseStatus = RuntimeSubsystemStatus.Starting;
    private RuntimeSubsystemStatus _trapStatus = RuntimeSubsystemStatus.Starting;
    private RuntimeSubsystemStatus _mibStatus = RuntimeSubsystemStatus.Normal;
    private string _acquisitionMessage = "Starting SNMP acquisition.";
    private string _redisOutputBaseMessage = "Waiting for Redis and Asset initialization.";
    private string _trapMessage = "Trap receiver is starting.";
    private string _mibMessage = "MIB metadata is optional.";
    private RuntimeState _current;

    public RuntimeModeService()
    {
        _current = BuildState(DateTimeOffset.UtcNow);
    }

    public event Action<RuntimeState>? Changed;

    public RuntimeState Current
    {
        get
        {
            lock (_sync)
            {
                return _current;
            }
        }
    }

    public bool IsNormal => Current.Mode == RuntimeMode.Normal;

    public bool IsRedisConnected => Current.RedisConnected;

    public bool IsAssetInitialized => Current.AssetInitialized;

    public void SetAcquisition(RuntimeSubsystemStatus status, string message)
    {
        Update(() =>
        {
            _acquisitionStatus = status;
            _acquisitionMessage = message;
        });
    }

    public void SetRedisOutput(
        RuntimeSubsystemStatus status,
        bool redisConnected,
        bool assetInitialized,
        string message)
    {
        Update(() =>
        {
            _redisOutputBaseStatus = status;
            _redisConnected = redisConnected;
            _assetInitialized = assetInitialized;
            _redisOutputBaseMessage = message;
        });
    }

    public void SetTrap(RuntimeSubsystemStatus status, string message)
    {
        Update(() =>
        {
            _trapStatus = status;
            _trapMessage = message;
        });
    }

    public void SetMib(RuntimeSubsystemStatus status, string message)
    {
        Update(() =>
        {
            _mibStatus = status;
            _mibMessage = message;
        });
    }

    public void ReplaceRedisOutputDiagnostics(
        string origin,
        IEnumerable<RedisOutputDiagnostic> diagnostics)
    {
        Update(() =>
        {
            var keys = _redisOutputDiagnostics
                .Where(item => item.Value.Origin.Equals(origin, StringComparison.OrdinalIgnoreCase))
                .Select(item => item.Key)
                .ToList();
            foreach (var key in keys)
            {
                _redisOutputDiagnostics.Remove(key);
            }

            foreach (var diagnostic in diagnostics)
            {
                _redisOutputDiagnostics[DiagnosticKey(diagnostic.Origin, diagnostic.SourcePath, diagnostic.RedisKey)] = diagnostic;
            }
        });
    }

    public void ReportRedisOutputDiagnostic(
        string origin,
        string sourcePath,
        string redisKey,
        string status,
        string message)
    {
        Update(() =>
        {
            var diagnostic = new RedisOutputDiagnostic(
                sourcePath,
                redisKey,
                status,
                message,
                origin,
                DateTimeOffset.UtcNow);
            _redisOutputDiagnostics[DiagnosticKey(origin, sourcePath, redisKey)] = diagnostic;
        });
    }

    public void ClearRedisOutputDiagnosticsForMapping(string sourcePath, string redisKey)
    {
        Update(() =>
        {
            var keys = _redisOutputDiagnostics
                .Where(item => item.Value.SourcePath.Equals(sourcePath, StringComparison.OrdinalIgnoreCase)
                               && item.Value.RedisKey.Equals(redisKey, StringComparison.OrdinalIgnoreCase))
                .Select(item => item.Key)
                .ToList();
            foreach (var key in keys)
            {
                _redisOutputDiagnostics.Remove(key);
            }
        });
    }

    public void Stop(string message = "Stopping")
    {
        Update(() =>
        {
            _acquisitionStatus = RuntimeSubsystemStatus.Stopping;
            _redisOutputBaseStatus = RuntimeSubsystemStatus.Stopping;
            _trapStatus = RuntimeSubsystemStatus.Stopping;
            _mibStatus = RuntimeSubsystemStatus.Stopping;
            _acquisitionMessage = message;
            _redisOutputBaseMessage = message;
            _trapMessage = message;
            _mibMessage = message;
        });
    }

    private void Update(Action mutate)
    {
        RuntimeState updated;
        bool changed;
        lock (_sync)
        {
            mutate();
            updated = BuildState(DateTimeOffset.UtcNow);
            changed = HasChanged(_current, updated);
            _current = updated;
        }

        if (changed)
        {
            Changed?.Invoke(updated);
        }
    }

    private RuntimeState BuildState(DateTimeOffset updatedAt)
    {
        var diagnostics = _redisOutputDiagnostics.Values
            .OrderBy(d => d.SourcePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(d => d.Origin, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var redisOutputStatus = diagnostics.Count > 0
            ? RuntimeSubsystemStatus.Degraded
            : _redisOutputBaseStatus;
        var redisOutputMessage = diagnostics.Count > 0
            ? $"Redis output degraded: {diagnostics[0].Message}"
            : _redisOutputBaseMessage;
        var mode = DeriveMode(_acquisitionStatus, redisOutputStatus, _trapStatus, _mibStatus);
        var message = BuildMessage(mode, _acquisitionStatus, _acquisitionMessage, redisOutputStatus, redisOutputMessage, _trapStatus, _trapMessage, _mibStatus, _mibMessage);

        return new RuntimeState(
            mode,
            _redisConnected,
            _assetInitialized,
            message,
            updatedAt,
            _acquisitionStatus,
            _acquisitionMessage,
            redisOutputStatus,
            redisOutputMessage,
            _trapStatus,
            _trapMessage,
            _mibStatus,
            _mibMessage,
            diagnostics);
    }

    private static RuntimeMode DeriveMode(params RuntimeSubsystemStatus[] statuses)
    {
        if (statuses.Any(status => status == RuntimeSubsystemStatus.Stopping))
        {
            return RuntimeMode.Stopping;
        }

        if (statuses.Any(status => status == RuntimeSubsystemStatus.Degraded))
        {
            return RuntimeMode.Degraded;
        }

        if (statuses.Any(status => status == RuntimeSubsystemStatus.Starting))
        {
            return RuntimeMode.Starting;
        }

        return RuntimeMode.Normal;
    }

    private static string BuildMessage(
        RuntimeMode mode,
        RuntimeSubsystemStatus acquisitionStatus,
        string acquisitionMessage,
        RuntimeSubsystemStatus redisOutputStatus,
        string redisOutputMessage,
        RuntimeSubsystemStatus trapStatus,
        string trapMessage,
        RuntimeSubsystemStatus mibStatus,
        string mibMessage)
    {
        if (mode == RuntimeMode.Normal)
        {
            return "SNMP acquisition, Redis output, trap receiver, and MIB metadata are normal.";
        }

        var parts = new[]
        {
            (Status: acquisitionStatus, Message: acquisitionMessage),
            (Status: redisOutputStatus, Message: redisOutputMessage),
            (Status: trapStatus, Message: trapMessage),
            (Status: mibStatus, Message: mibMessage)
        };

        return string.Join(" ", parts.Where(part => part.Status != RuntimeSubsystemStatus.Normal).Select(part => part.Message));
    }

    private static bool HasChanged(RuntimeState current, RuntimeState updated) =>
        current.Mode != updated.Mode
        || current.RedisConnected != updated.RedisConnected
        || current.AssetInitialized != updated.AssetInitialized
        || current.AcquisitionStatus != updated.AcquisitionStatus
        || current.RedisOutputStatus != updated.RedisOutputStatus
        || current.TrapStatus != updated.TrapStatus
        || current.MibStatus != updated.MibStatus
        || !string.Equals(current.Message, updated.Message, StringComparison.Ordinal)
        || !string.Equals(current.AcquisitionMessage, updated.AcquisitionMessage, StringComparison.Ordinal)
        || !string.Equals(current.RedisOutputMessage, updated.RedisOutputMessage, StringComparison.Ordinal)
        || !string.Equals(current.TrapMessage, updated.TrapMessage, StringComparison.Ordinal)
        || !string.Equals(current.MibMessage, updated.MibMessage, StringComparison.Ordinal)
        || !DiagnosticsEqual(current.RedisOutputDiagnostics, updated.RedisOutputDiagnostics);

    private static bool DiagnosticsEqual(
        IReadOnlyList<RedisOutputDiagnostic> current,
        IReadOnlyList<RedisOutputDiagnostic> updated)
    {
        if (current.Count != updated.Count)
        {
            return false;
        }

        for (var i = 0; i < current.Count; i++)
        {
            var left = current[i];
            var right = updated[i];
            if (!left.SourcePath.Equals(right.SourcePath, StringComparison.Ordinal)
                || !left.RedisKey.Equals(right.RedisKey, StringComparison.Ordinal)
                || !left.Status.Equals(right.Status, StringComparison.Ordinal)
                || !left.Message.Equals(right.Message, StringComparison.Ordinal)
                || !left.Origin.Equals(right.Origin, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static string DiagnosticKey(string origin, string sourcePath, string redisKey) =>
        $"{origin}|{sourcePath}|{redisKey}";
}
