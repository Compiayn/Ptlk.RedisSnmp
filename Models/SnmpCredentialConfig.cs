namespace Ptlk.RedisSnmp.Models;

public sealed class SnmpCredentialConfig
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Version { get; set; } = "v2c";
    public string? ProtectedCommunity { get; set; }
    public string? SecurityName { get; set; }
    public string? SecurityLevel { get; set; }
    public string? AuthProtocol { get; set; }
    public string? ProtectedAuthPassword { get; set; }
    public string? PrivProtocol { get; set; }
    public string? ProtectedPrivPassword { get; set; }
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
