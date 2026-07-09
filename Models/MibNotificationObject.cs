namespace Ptlk.RedisSnmp.Models;

public sealed class MibNotificationObject
{
    public int Id { get; set; }
    public int NotificationMibNodeId { get; set; }
    public MibNode? NotificationMibNode { get; set; }
    public int SortOrder { get; set; }
    public string ObjectSymbol { get; set; } = "";
    public string? ObjectOid { get; set; }
}
