namespace Ptlk.RedisSnmp.Models;

public sealed class MibFile
{
    public int Id { get; set; }
    public int MibSetId { get; set; }
    public MibSet? MibSet { get; set; }
    public string FileName { get; set; } = "";
    public string? StoredPath { get; set; }
    public string? ModuleName { get; set; }
    public string? ModuleIdentityOid { get; set; }
    public string Hash { get; set; } = "";
    public string ValidationStatus { get; set; } = "";
    public string? ErrorMessage { get; set; }
    public string? RawContent { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public List<MibNode> Nodes { get; set; } = [];
}
