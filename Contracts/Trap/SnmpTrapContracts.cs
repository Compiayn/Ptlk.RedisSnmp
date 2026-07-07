namespace Ptlk.RedisSnmp.Contracts.Trap;

public sealed record SnmpTrapVarbind(
    string Oid,
    string? Value,
    string? Syntax,
    string? Label);

public sealed record SnmpTrapMessage(
    string AgentId,
    string SourceAddress,
    string TrapOid,
    IReadOnlyList<SnmpTrapVarbind> Varbinds,
    DateTimeOffset ReceivedAt,
    string RawPayload);
