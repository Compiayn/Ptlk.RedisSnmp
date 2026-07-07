namespace Ptlk.RedisSnmp.Models;

public sealed class SnmpPointConfig
{
    public int Id { get; set; }
    public int AgentConfigId { get; set; }
    public SnmpAgentConfig? AgentConfig { get; set; }
    public string PointName { get; set; } = "";
    public string SourcePath { get; set; } = "";
    public string NumericOid { get; set; } = "";
    public string ValueType { get; set; } = "string";
    public bool PollEnabled { get; set; } = true;
    public bool SetEnabled { get; set; }
    public string Access { get; set; } = "ro";
    public string? Description { get; set; }
    public string? MibLabel { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
