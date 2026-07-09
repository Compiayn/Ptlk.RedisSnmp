namespace Ptlk.RedisSnmp.Contracts.Trap;

public static class TrapPublishModes
{
    public const string Open = "Open";
    public const string Credential = "Credential";

    public static bool IsValid(string? value) =>
        string.Equals(value, Open, StringComparison.OrdinalIgnoreCase)
        || string.Equals(value, Credential, StringComparison.OrdinalIgnoreCase);

    public static string Normalize(string? value) =>
        string.Equals(value, Open, StringComparison.OrdinalIgnoreCase) ? Open : Credential;
}

public static class TrapAgentResolutionResults
{
    public const string Resolved = "Resolved";
    public const string Unresolved = "Unresolved";
    public const string Ambiguous = "Ambiguous";
    public const string Disabled = "Disabled";
}

public static class TrapCredentialValidationResults
{
    public const string Accepted = "Accepted";
    public const string Rejected = "Rejected";
    public const string NotApplicable = "NotApplicable";
    public const string NotConfigured = "NotConfigured";
    public const string Disabled = "Disabled";
}

public static class TrapPublishResults
{
    public const string Published = "Published";
    public const string Skipped = "Skipped";
}

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
    string RawPayload)
{
    public int? SourcePort { get; init; }
    public string? Version { get; init; }
    public string? Community { get; init; }
    public string? SecurityName { get; init; }
    public string? SecurityLevel { get; init; }
    public string? EngineId { get; init; }
}
