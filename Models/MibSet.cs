namespace Ptlk.RedisSnmp.Models;

public sealed class MibSet
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public string Status { get; set; } = "draft";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public List<MibFile> Files { get; set; } = [];
    public List<MibNode> Nodes { get; set; } = [];
    public List<MibSetValidationIssue> ValidationIssues { get; set; } = [];
}
