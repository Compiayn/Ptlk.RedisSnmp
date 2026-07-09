namespace Ptlk.RedisSnmp.Models;

public sealed class ExpressionBinding
{
    public int Id { get; set; }
    public int ExpressionConfigId { get; set; }
    public ExpressionConfig? ExpressionConfig { get; set; }
    public string ParameterName { get; set; } = "";
    public string SourcePath { get; set; } = "";
}
