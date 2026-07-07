namespace Ptlk.RedisSnmp.Models;

public sealed class MibSetValidationIssue
{
    public int Id { get; set; }
    public int MibSetId { get; set; }
    public MibSet? MibSet { get; set; }
    public string Severity { get; set; } = "warning";
    public string Code { get; set; } = "";
    public string Message { get; set; } = "";
    public string? ModuleName { get; set; }
    public string? NumericOid { get; set; }
    public string? SymbolicName { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
