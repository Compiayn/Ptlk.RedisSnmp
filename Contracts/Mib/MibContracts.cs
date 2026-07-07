namespace Ptlk.RedisSnmp.Contracts.Mib;

public sealed record MibLookupResult(
    string NumericOid,
    string? SymbolicName,
    string? ModuleName,
    string? Syntax,
    string? Access,
    string? Description);

public sealed record MibImportResult(
    bool Success,
    string ImportId,
    string VersionName,
    int NodeCount,
    IReadOnlyList<string> Errors);

public sealed record ProjectMibExport(
    string FileName,
    string ContentType,
    string Content);
