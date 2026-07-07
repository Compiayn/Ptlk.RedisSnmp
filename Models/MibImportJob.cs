namespace Ptlk.RedisSnmp.Models;

public sealed class MibImportJob
{
    public int Id { get; set; }
    public int? MibSetId { get; set; }
    public MibSet? MibSet { get; set; }
    public string ImportId { get; set; } = Guid.NewGuid().ToString("N");
    public string VersionName { get; set; } = "";
    public string Status { get; set; } = "staging";
    public string? SourceFileName { get; set; }
    public string? ErrorMessage { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
