namespace Ptlk.RedisSnmp.Contracts.Mib;

public sealed record MibLookupResult(
    string NumericOid,
    string? SymbolicName,
    string? ModuleName,
    string? Syntax,
    string? Access,
    string? Description,
    int? MibSetId = null);

public sealed record MibImportResult(
    bool Success,
    string ImportId,
    string VersionName,
    int NodeCount,
    IReadOnlyList<string> Errors,
    int? MibSetId = null);

public sealed record ProjectMibExport(
    string FileName,
    string ContentType,
    string Content);

public sealed record MibSetSummary(
    int Id,
    string Name,
    string? Description,
    string Status,
    int FileCount,
    int NodeCount,
    int IssueCount,
    int ErrorCount,
    int AgentReferenceCount,
    int PointReferenceCount,
    DateTime UpdatedAt);

public sealed record MibSetOption(int Id, string Name, string Status);

public sealed record MibSetReference(string Kind, string Name, string Detail);

public sealed record DefaultMibFileSummary(
    string FileName,
    string RelativePath,
    string RelativeDirectory,
    long Size,
    DateTime UpdatedAt);

public sealed record MibSetValidationResult(
    int IssueCount,
    int ErrorCount,
    IReadOnlyList<string> Messages);

public sealed record MibSetSnapshotRefreshResult(
    bool Success,
    int NodeCount,
    int IssueCount,
    int ErrorCount,
    IReadOnlyList<string> Messages);

public sealed record MibSetDeleteResult(
    bool Success,
    IReadOnlyList<MibSetReference> References);

public static class MibSetStatuses
{
    public const string Draft = "draft";
    public const string SnapshotStale = "snapshot-stale";
    public const string Available = "available";
}

public static class MibFileValidationStatuses
{
    public const string Parsed = "parsed";
    public const string Validated = "validated";
    public const string Failed = "failed";
}

public static class MibValidationSeverities
{
    public const string Info = "info";
    public const string Warning = "warning";
    public const string Error = "error";
}
