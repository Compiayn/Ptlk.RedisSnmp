namespace Ptlk.RedisSnmp.Models;

public sealed class SnmpLogEntry
{
    public int Id { get; set; }
    public int? AgentConfigId { get; set; }
    public SnmpAgentConfig? AgentConfig { get; set; }
    public int? PointConfigId { get; set; }
    public SnmpPointConfig? PointConfig { get; set; }
    public string? AgentId { get; set; }
    public string? NumericOid { get; set; }
    public string Operation { get; set; } = "";
    public string Level { get; set; } = "Info";
    public string Message { get; set; } = "";
    public string? CommandId { get; set; }
    public string? ErrorCode { get; set; }
    public int? DurationMs { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
