namespace Ptlk.RedisSnmp.Models;

public sealed class MibNode
{
    public int Id { get; set; }
    public string VersionName { get; set; } = "";
    public string NumericOid { get; set; } = "";
    public string? SymbolicName { get; set; }
    public string? ModuleName { get; set; }
    public string? Syntax { get; set; }
    public string? Access { get; set; }
    public string? Description { get; set; }
    public bool Active { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
