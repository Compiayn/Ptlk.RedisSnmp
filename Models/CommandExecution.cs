namespace Ptlk.RedisSnmp.Models;

public sealed class CommandExecution
{
    public int Id { get; set; }
    public string CommandId { get; set; } = "";
    public string Status { get; set; } = "accepted";
    public string RedisKey { get; set; } = "";
    public string RequestedPayload { get; set; } = "";
    public string? ResultPayload { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
