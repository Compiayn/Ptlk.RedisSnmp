using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Contracts.Mib;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Paths;
using Ptlk.RedisSnmp.Services.Startup;

namespace Ptlk.RedisSnmp.Services.Mib;

public sealed class MibImportService(
    AppDbContext db,
    SnmpSourcePathService paths,
    RuntimeModeService runtime)
{
    public async Task<MibImportResult> ImportTextAsync(
        string versionName,
        string sourceFileName,
        string content,
        bool activate,
        CancellationToken cancellationToken = default)
    {
        var importId = Guid.NewGuid().ToString("N");
        var job = new MibImportJob
        {
            ImportId = importId,
            VersionName = versionName.Trim(),
            SourceFileName = sourceFileName,
            Status = "staging"
        };
        db.MibImportJobs.Add(job);

        var errors = new List<string>();
        var nodes = new List<MibNode>();
        var lineNumber = 0;
        foreach (var line in content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            lineNumber++;
            var trimmed = line.Trim();
            if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith('#'))
            {
                continue;
            }

            var parts = trimmed.Split(',', StringSplitOptions.TrimEntries);
            if (parts.Length < 2)
            {
                errors.Add($"Line {lineNumber}: expected numeric_oid,symbolic_name.");
                continue;
            }

            try
            {
                nodes.Add(new MibNode
                {
                    VersionName = job.VersionName,
                    NumericOid = paths.NormalizeNumericOid(parts[0]),
                    SymbolicName = EmptyToNull(parts.ElementAtOrDefault(1)),
                    ModuleName = EmptyToNull(parts.ElementAtOrDefault(2)),
                    NodeKind = EmptyToNull(parts.ElementAtOrDefault(6)),
                    Syntax = EmptyToNull(parts.ElementAtOrDefault(3)),
                    Access = EmptyToNull(parts.ElementAtOrDefault(4)),
                    Description = EmptyToNull(parts.ElementAtOrDefault(5)),
                    Active = activate
                });
            }
            catch (Exception ex)
            {
                errors.Add($"Line {lineNumber}: {ex.Message}");
            }
        }

        if (errors.Count > 0)
        {
            job.Status = "failed";
            job.ErrorMessage = string.Join(Environment.NewLine, errors.Take(20));
            await db.SaveChangesAsync(cancellationToken);
            runtime.SetMib(RuntimeSubsystemStatus.Degraded, $"MIB import failed: {errors[0]}");
            return new MibImportResult(false, importId, job.VersionName, 0, errors);
        }

        if (activate)
        {
            await db.MibNodes.Where(node => node.Active).ExecuteUpdateAsync(
                setters => setters.SetProperty(node => node.Active, false),
                cancellationToken);
        }

        db.MibNodes.AddRange(nodes);
        job.Status = activate ? "activated" : "succeeded";
        await db.SaveChangesAsync(cancellationToken);
        runtime.SetMib(RuntimeSubsystemStatus.Normal, activate ? $"Active MIB version: {job.VersionName}." : $"Imported MIB version: {job.VersionName}.");

        return new MibImportResult(true, importId, job.VersionName, nodes.Count, []);
    }

    public async Task ActivateAsync(string versionName, CancellationToken cancellationToken = default)
    {
        await db.MibNodes.Where(node => node.Active).ExecuteUpdateAsync(
            setters => setters.SetProperty(node => node.Active, false),
            cancellationToken);
        await db.MibNodes.Where(node => node.VersionName == versionName).ExecuteUpdateAsync(
            setters => setters.SetProperty(node => node.Active, true),
            cancellationToken);
        runtime.SetMib(RuntimeSubsystemStatus.Normal, $"Active MIB version: {versionName}.");
    }

    public Task<List<MibImportJob>> ListJobsAsync(CancellationToken cancellationToken = default) =>
        db.MibImportJobs.AsNoTracking().OrderByDescending(job => job.CreatedAt).Take(100).ToListAsync(cancellationToken);

    private static string? EmptyToNull(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
