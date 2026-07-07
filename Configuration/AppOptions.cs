using Microsoft.Extensions.Options;

namespace Ptlk.RedisSnmp.Configuration;

public sealed class RedisOptions
{
    public string Host { get; set; } = "localhost";
    public int Port { get; set; } = 6379;
    public string? AclUsername { get; set; }
    public string? AclPassword { get; set; }
    public int DatabaseIndex { get; set; }
    public int ConnectTimeoutMs { get; set; } = 5000;
    public int SyncTimeoutMs { get; set; } = 3000;
    public bool AbortConnect { get; set; }
    public int ConnectRetry { get; set; } = 3;
    public int KeepAliveSeconds { get; set; } = 60;
    public bool Ssl { get; set; }
}

public sealed class RedisSnmpOptions
{
    public string ConverterId { get; set; } = "redis-snmp-local-1";
    public string SourceName { get; set; } = "redis-snmp";
}

public sealed class StartupGateOptions
{
    public int WaitInitializedTimeoutMs { get; set; } = 60000;
    public int InitialRetryDelayMs { get; set; } = 250;
    public int MaxRetryDelayMs { get; set; } = 5000;
}

public sealed class RedisSnmpRuntimeOptions
{
    public int HeartbeatIntervalMs { get; set; } = 10000;
    public int CommandDefaultTimeoutMs { get; set; } = 5000;
}

public sealed class SnmpRuntimeOptions
{
    public int DefaultPollingRateMs { get; set; } = 1000;
    public int DefaultTimeoutMs { get; set; } = 5000;
    public int DefaultWalkTimeoutMs { get; set; } = 60000;
    public int DefaultRetryCount { get; set; } = 1;
}

public sealed class NetSnmpOptions
{
    public string ToolsPath { get; set; } = "";
    public string MibDirectory { get; set; } = "/data/mibs";
    public string DefaultMibDirectory { get; set; } = "";
    public string WorkDirectory { get; set; } = "/data/snmp";
}

public sealed class TrapOptions
{
    public bool Enabled { get; set; } = true;
    public int ListenPort { get; set; } = 10162;
    public int BufferLimit { get; set; } = 1000;
}

public sealed class BrowserOptions
{
    public int RefreshIntervalMs { get; set; } = 1000;
}

public sealed class ImportExportOptions
{
    public long SingleCsvLimitBytes { get; set; } = 10 * 1024 * 1024;
    public long ZipFileLimitBytes { get; set; } = 50 * 1024 * 1024;
    public long ZipExtractedLimitBytes { get; set; } = 50 * 1024 * 1024;
}

public static class OptionsRegistration
{
    public static IServiceCollection AddRedisSnmpOptions(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<RedisOptions>()
            .Bind(configuration.GetSection("Redis"))
            .Validate(o => !string.IsNullOrWhiteSpace(o.Host)
                           && o.Port is > 0 and <= 65535
                           && o.DatabaseIndex >= 0
                           && o.ConnectTimeoutMs > 0
                           && o.SyncTimeoutMs > 0
                           && o.ConnectRetry >= 0
                           && o.KeepAliveSeconds > 0,
                "Redis options are invalid.")
            .ValidateOnStart();

        services.AddOptions<RedisSnmpOptions>()
            .Bind(configuration.GetSection("RedisSnmp"))
            .Validate(o => IsSafeToken(o.ConverterId)
                           && IsSafeToken(o.SourceName),
                "RedisSnmp identifiers must be non-empty and must not contain Redis separator characters.")
            .ValidateOnStart();

        services.AddOptions<StartupGateOptions>()
            .Bind(configuration.GetSection("StartupGate"))
            .Validate(o => o.WaitInitializedTimeoutMs > 0
                           && o.InitialRetryDelayMs > 0
                           && o.MaxRetryDelayMs >= o.InitialRetryDelayMs,
                "StartupGate retry settings are invalid.")
            .ValidateOnStart();

        services.AddOptions<RedisSnmpRuntimeOptions>()
            .Bind(configuration.GetSection("RedisSnmpRuntime"))
            .Validate(o => o.HeartbeatIntervalMs > 0 && o.CommandDefaultTimeoutMs > 0,
                "RedisSnmpRuntime options are invalid.")
            .ValidateOnStart();

        services.AddOptions<SnmpRuntimeOptions>()
            .Bind(configuration.GetSection("SnmpRuntime"))
            .Validate(o => o.DefaultPollingRateMs >= 100
                           && o.DefaultTimeoutMs > 0
                           && o.DefaultWalkTimeoutMs > 0
                           && o.DefaultRetryCount >= 0,
                "SnMP runtime options are invalid.")
            .ValidateOnStart();

        services.AddOptions<NetSnmpOptions>()
            .Bind(configuration.GetSection("NetSnmp"))
            .Validate(o => !string.IsNullOrWhiteSpace(o.MibDirectory)
                           && !string.IsNullOrWhiteSpace(o.WorkDirectory),
                "Net-SNMP paths are invalid.")
            .ValidateOnStart();

        services.AddOptions<TrapOptions>()
            .Bind(configuration.GetSection("Trap"))
            .Validate(o => o.ListenPort is > 0 and <= 65535
                           && o.BufferLimit > 0,
                "Trap options are invalid.")
            .ValidateOnStart();

        services.AddOptions<BrowserOptions>()
            .Bind(configuration.GetSection("Browser"))
            .Validate(o => o.RefreshIntervalMs >= 500,
                "Browser refresh interval must be at least 500 ms.")
            .ValidateOnStart();

        services.AddOptions<ImportExportOptions>()
            .Bind(configuration.GetSection("ImportExport"))
            .Validate(o => o.SingleCsvLimitBytes > 0
                           && o.ZipFileLimitBytes > 0
                           && o.ZipExtractedLimitBytes >= o.SingleCsvLimitBytes,
                "Import/export file limits are invalid.")
            .ValidateOnStart();

        return services;
    }

    private static bool IsSafeToken(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && !value.Contains(':', StringComparison.Ordinal)
        && !value.Contains('*', StringComparison.Ordinal)
        && !value.Contains(' ', StringComparison.Ordinal)
        && !value.Contains('/', StringComparison.Ordinal)
        && !value.Contains('\\', StringComparison.Ordinal);
}
