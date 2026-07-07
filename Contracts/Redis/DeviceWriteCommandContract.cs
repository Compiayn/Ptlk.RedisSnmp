using System.Text.Json;

namespace Ptlk.RedisSnmp.Contracts.Redis;

public sealed class DeviceWriteCommandContract
{
    public int Schema { get; set; } = 1;
    public string Type { get; set; } = "command.write-requested";
    public string MessageId { get; set; } = Guid.NewGuid().ToString("N");
    public string CommandId { get; set; } = "";
    public string Key { get; set; } = "";
    public JsonElement Value { get; set; }
    public long? ExpectedVersion { get; set; }
    public int? TimeoutMs { get; set; }
    public int? Priority { get; set; }
    public JsonElement? Params { get; set; }
    public string RequestedBy { get; set; } = "";
    public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    public string Source { get; set; } = "";

    public string ValueAsString() =>
        Value.ValueKind switch
        {
            JsonValueKind.String => Value.GetString() ?? "",
            JsonValueKind.Number => Value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => "",
            JsonValueKind.Undefined => "",
            _ => Value.GetRawText()
        };
}
