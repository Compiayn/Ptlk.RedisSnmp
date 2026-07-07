namespace Ptlk.RedisSnmp.Models;

public sealed class RedisMapping
{
    public int Id { get; set; }
    public string SourcePath { get; set; } = "";
    public string RedisKey { get; set; } = "";
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
