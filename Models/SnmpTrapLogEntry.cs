namespace Ptlk.RedisSnmp.Models;

public sealed class SnmpTrapLogEntry
{
    public int Id { get; set; }
    public DateTime ReceivedAt { get; set; } = DateTime.UtcNow;
    public string? AgentId { get; set; }
    public string SourceAddress { get; set; } = "";
    public int? TransportSourcePort { get; set; }
    public string TrapOid { get; set; } = "";
    public string VarbindsJson { get; set; } = "[]";
    public string? MibLabelsJson { get; set; }
    public string RawPayload { get; set; } = "";
    public string ResolvedPayload { get; set; } = "{}";
    public string? ExpectedObjects { get; set; }
    public string? ExpectedObjectMatchResult { get; set; }
    public string? ResolvedAgentId { get; set; }
    public string AgentResolutionResult { get; set; } = "";
    public string AgentResolutionReason { get; set; } = "";
    public string? ResolvedTrapOid { get; set; }
    public string? ResolvedTrapName { get; set; }
    public string? ResolvedTrapModule { get; set; }
    public string? ResolvedTrapDescription { get; set; }
    public string PublishMode { get; set; } = "";
    public string CredentialValidationResult { get; set; } = "";
    public string CredentialValidationReason { get; set; } = "";
    public string PublishResult { get; set; } = "";
    public string PublishReason { get; set; } = "";
}
