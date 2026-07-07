namespace Ptlk.RedisSnmp.Models;

public sealed class SnmpTrapRuleConfig
{
    public int Id { get; set; }
    public string AgentId { get; set; } = "";
    public string TrapOid { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
