namespace Ptlk.RedisSnmp.Models;

public sealed class SnmpAgentConfig
{
    public int Id { get; set; }
    public string AgentId { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 161;
    public string SnmpVersion { get; set; } = "v2c";
    public int? CredentialConfigId { get; set; }
    public SnmpCredentialConfig? CredentialConfig { get; set; }
    public int TimeoutMs { get; set; } = 5000;
    public int RetryCount { get; set; } = 1;
    public int PollingRateMs { get; set; } = 1000;
    public bool Enabled { get; set; } = true;
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public List<SnmpPointConfig> Points { get; set; } = [];
}
