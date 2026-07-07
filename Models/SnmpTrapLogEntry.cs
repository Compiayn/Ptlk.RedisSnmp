namespace Ptlk.RedisSnmp.Models;

public sealed class SnmpTrapLogEntry
{
    public int Id { get; set; }
    public DateTime ReceivedAt { get; set; } = DateTime.UtcNow;
    public string AgentId { get; set; } = "unknown";
    public string SourceAddress { get; set; } = "";
    public string TrapOid { get; set; } = "";
    public string VarbindsJson { get; set; } = "[]";
    public string? MibLabelsJson { get; set; }
    public string RawPayload { get; set; } = "";
}
