namespace Ptlk.RedisSnmp.Contracts.Snmp;

public sealed record NetSnmpCommandArguments(
    string Tool,
    IReadOnlyList<string> Arguments,
    IReadOnlyList<string> RedactedArguments);

public sealed record NetSnmpProcessResult(
    string Tool,
    IReadOnlyList<string> Arguments,
    IReadOnlyList<string> RedactedArguments,
    int ExitCode,
    string StandardOutput,
    string StandardError,
    TimeSpan Duration,
    bool TimedOut,
    string? ErrorCode);

public sealed record SnmpGetResult(
    bool Success,
    string Oid,
    string? Value,
    string? Syntax,
    string RawOutput,
    string? ErrorCode,
    string? ErrorMessage);

public sealed record SnmpWalkItem(string Oid, string? Value, string? Syntax, string RawLine);

public sealed record SnmpWalkResult(
    bool Success,
    IReadOnlyList<SnmpWalkItem> Items,
    string RawOutput,
    string? ErrorCode,
    string? ErrorMessage);

public sealed record SnmpSetResult(
    bool Success,
    string Oid,
    string? Value,
    string? Syntax,
    string RawOutput,
    string? ErrorCode,
    string? ErrorMessage);

public sealed record SnmpTranslateResult(
    bool Success,
    string Input,
    string? NumericOid,
    string? SymbolicName,
    string RawOutput,
    string? ErrorCode,
    string? ErrorMessage);

public sealed record SnmpPollPointResult(
    string SourcePath,
    string? Value,
    string Quality,
    string? ErrorCode,
    string? ErrorMessage,
    string? RawValue);
