using Ptlk.RedisSnmp.Services.Expressions;

namespace Ptlk.RedisSnmp.Models;

public sealed class ExpressionConfig
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public string Rw { get; set; } = "Ro";
    public string ValueType { get; set; } = ExpressionValueTypes.Double;
    public string? ReadReturnParameter { get; set; }
    public string? ReadScript { get; set; }
    public string? WriteInputParameter { get; set; }
    public string? WriteScript { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public List<ExpressionBinding> Bindings { get; set; } = [];
}
