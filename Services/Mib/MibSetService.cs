using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Mib;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Paths;
using Ptlk.RedisSnmp.Services.Snmp;
using Ptlk.RedisSnmp.Services.Startup;

namespace Ptlk.RedisSnmp.Services.Mib;

public sealed class MibSetService(
    AppDbContext db,
    SnmpSourcePathService paths,
    RuntimeModeService runtime,
    IOptions<NetSnmpOptions> netSnmpOptions,
    IHostEnvironment? hostEnvironment = null,
    SnmpClientService? snmp = null)
{
    private static readonly Regex ModuleNamePattern = new(
        @"^\s*(?<module>[A-Za-z][A-Za-z0-9-]*)\s+DEFINITIONS\s*::=",
        RegexOptions.Compiled | RegexOptions.Multiline);

    private static readonly Regex ImportModulePattern = new(
        @"\bFROM\s+(?<module>[A-Za-z][A-Za-z0-9-]*)",
        RegexOptions.Compiled | RegexOptions.Multiline);

    private static readonly Regex MibObjectPattern = new(
        @"(?ms)^\s*(?<symbol>[A-Za-z][A-Za-z0-9-]*)\s+(?<kind>MODULE-IDENTITY|OBJECT-TYPE|OBJECT-IDENTITY|NOTIFICATION-TYPE|OBJECT IDENTIFIER)\b(?<body>.*?::=\s*\{(?<assignment>[^}]*)\})",
        RegexOptions.Compiled | RegexOptions.Multiline);

    private static readonly Regex AssignmentTokenPattern = new(
        @"(?<name>[A-Za-z][A-Za-z0-9-]*)(?:\((?<number>\d+)\))?|(?<number>\d+)|(?<oid>\.?[0-9][0-9.]*)",
        RegexOptions.Compiled);

    private static readonly Regex SyntaxPattern = new(
        @"(?m)^\s*SYNTAX\s+(?<value>[^\r\n]+)",
        RegexOptions.Compiled);

    private static readonly Regex AccessPattern = new(
        @"(?m)^\s*(?:MAX-ACCESS|ACCESS)\s+(?<value>[^\r\n]+)",
        RegexOptions.Compiled);

    private static readonly Regex DescriptionPattern = new(
        "DESCRIPTION\\s+\"(?<value>(?:[^\"]|\"\")*)\"",
        RegexOptions.Compiled | RegexOptions.Singleline);

    private static readonly Regex CommentPattern = new(
        @"--.*$",
        RegexOptions.Compiled | RegexOptions.Multiline);

    private static readonly Dictionary<string, string> BuiltInOidRoots = new(StringComparer.OrdinalIgnoreCase)
    {
        ["iso"] = "1",
        ["org"] = "1.3",
        ["dod"] = "1.3.6",
        ["internet"] = "1.3.6.1",
        ["directory"] = "1.3.6.1.1",
        ["mgmt"] = "1.3.6.1.2",
        ["mib-2"] = "1.3.6.1.2.1",
        ["transmission"] = "1.3.6.1.2.1.10",
        ["experimental"] = "1.3.6.1.3",
        ["private"] = "1.3.6.1.4",
        ["enterprises"] = "1.3.6.1.4.1",
        ["snmpV2"] = "1.3.6.1.6",
        ["snmpModules"] = "1.3.6.1.6.3",
        ["system"] = "1.3.6.1.2.1.1",
        ["interfaces"] = "1.3.6.1.2.1.2"
    };

    public async Task<List<MibSetSummary>> ListAsync(CancellationToken cancellationToken = default)
    {
        var sets = await db.MibSets
            .AsNoTracking()
            .OrderBy(s => s.Name)
            .Select(s => new
            {
                s.Id,
                s.Name,
                s.Description,
                s.Status,
                s.UpdatedAt,
                FileCount = s.Files.Count,
                NodeCount = s.Nodes.Count,
                IssueCount = s.ValidationIssues.Count,
                ErrorCount = s.ValidationIssues.Count(i => i.Severity == MibValidationSeverities.Error)
            })
            .ToListAsync(cancellationToken);

        var agentReferences = await db.SnmpAgentConfigs
            .AsNoTracking()
            .Where(a => a.PreferredMibSetId != null)
            .GroupBy(a => a.PreferredMibSetId!.Value)
            .Select(g => new { MibSetId = g.Key, Count = g.Count() })
            .ToDictionaryAsync(g => g.MibSetId, g => g.Count, cancellationToken);

        var pointReferences = await db.SnmpPointConfigs
            .AsNoTracking()
            .Where(p => p.MibSetIdUsedForMapping != null)
            .GroupBy(p => p.MibSetIdUsedForMapping!.Value)
            .Select(g => new { MibSetId = g.Key, Count = g.Count() })
            .ToDictionaryAsync(g => g.MibSetId, g => g.Count, cancellationToken);

        return sets.Select(s => new MibSetSummary(
                s.Id,
                s.Name,
                s.Description,
                NormalizeSetStatus(s.Status),
                s.FileCount,
                s.NodeCount,
                s.IssueCount,
                s.ErrorCount,
                agentReferences.GetValueOrDefault(s.Id),
                pointReferences.GetValueOrDefault(s.Id),
                s.UpdatedAt))
            .ToList();
    }

    public async Task<List<MibSetOption>> ListOptionsAsync(CancellationToken cancellationToken = default)
    {
        var sets = await db.MibSets.AsNoTracking()
            .OrderBy(s => s.Name)
            .Select(s => new MibSetOption(s.Id, s.Name, s.Status))
            .ToListAsync(cancellationToken);

        return sets.Select(s => s with { Status = NormalizeSetStatus(s.Status) }).ToList();
    }

    public async Task<MibSet?> GetAsync(int id, CancellationToken cancellationToken = default)
    {
        var set = await db.MibSets.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, cancellationToken);
        if (set is not null)
        {
            set.Status = NormalizeSetStatus(set.Status);
        }

        return set;
    }

    public async Task<MibSet> CreateOrUpdateAsync(MibSet input, CancellationToken cancellationToken = default)
    {
        ValidateSet(input);

        var entity = input.Id > 0
            ? await db.MibSets.FirstAsync(s => s.Id == input.Id, cancellationToken)
            : new MibSet();

        entity.Name = input.Name.Trim();
        entity.Description = NullIfWhiteSpace(input.Description);
        entity.Status = NormalizeSetStatus(entity.Status);

        if (input.Id <= 0)
        {
            entity.Status = MibSetStatuses.Draft;
            db.MibSets.Add(entity);
        }

        await db.SaveChangesAsync(cancellationToken);
        return entity;
    }

    public async Task<MibSetDeleteResult> DeleteAsync(int mibSetId, CancellationToken cancellationToken = default)
    {
        var references = await ListReferencesAsync(mibSetId, cancellationToken);
        if (references.Count > 0)
        {
            return new MibSetDeleteResult(false, references);
        }

        var set = await db.MibSets
            .Include(s => s.Files)
            .FirstOrDefaultAsync(s => s.Id == mibSetId, cancellationToken);
        if (set is null)
        {
            return new MibSetDeleteResult(true, []);
        }

        var storedPaths = set.Files
            .Select(f => f.StoredPath)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Cast<string>()
            .ToList();

        db.MibSets.Remove(set);
        await db.SaveChangesAsync(cancellationToken);

        var cleanupFailures = new List<string>();
        foreach (var storedPath in storedPaths)
        {
            try
            {
                DeleteStoredFile(storedPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                cleanupFailures.Add($"{storedPath}: {ex.Message}");
            }
        }

        runtime.SetMib(
            cleanupFailures.Count == 0 ? RuntimeSubsystemStatus.Normal : RuntimeSubsystemStatus.Degraded,
            cleanupFailures.Count == 0
                ? $"Deleted MIB set {set.Name}."
                : $"Deleted MIB set {set.Name}, but {cleanupFailures.Count} stored file(s) could not be removed.");
        return new MibSetDeleteResult(true, []);
    }

    public Task<List<MibFile>> ListFilesAsync(int mibSetId, CancellationToken cancellationToken = default) =>
        db.MibFiles.AsNoTracking()
            .Where(f => f.MibSetId == mibSetId)
            .OrderByDescending(f => f.CreatedAt)
            .ToListAsync(cancellationToken);

    public Task<List<DefaultMibFileSummary>> ListDefaultMibFilesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var root = DefaultMibRoot();
        var files = EnumerateDefaultMibFilePaths(root)
            .Select(path =>
            {
                var info = new FileInfo(path);
                var relativePath = ToDefaultRelativePath(root, path);
                var relativeDirectory = Path.GetDirectoryName(relativePath)?.Replace('\\', '/') ?? "";
                return new DefaultMibFileSummary(
                    info.Name,
                    relativePath,
                    relativeDirectory,
                    info.Length,
                    info.LastWriteTimeUtc);
            })
            .ToList();

        return Task.FromResult(files);
    }

    public async Task<string> ReadDefaultMibFileContentAsync(
        string relativePath,
        CancellationToken cancellationToken = default)
    {
        var path = ResolveDefaultMibPath(relativePath);
        return await File.ReadAllTextAsync(path, Encoding.UTF8, cancellationToken);
    }

    public Task<List<MibSetValidationIssue>> ListIssuesAsync(int mibSetId, CancellationToken cancellationToken = default) =>
        db.MibSetValidationIssues.AsNoTracking()
            .Where(i => i.MibSetId == mibSetId)
            .OrderByDescending(i => i.Severity == MibValidationSeverities.Error)
            .ThenBy(i => i.Code)
            .ThenBy(i => i.NumericOid)
            .ThenBy(i => i.SymbolicName)
            .ToListAsync(cancellationToken);

    public async Task<List<MibSetReference>> ListReferencesAsync(int mibSetId, CancellationToken cancellationToken = default)
    {
        var references = new List<MibSetReference>();
        var agents = await db.SnmpAgentConfigs.AsNoTracking()
            .Where(a => a.PreferredMibSetId == mibSetId)
            .OrderBy(a => a.AgentId)
            .Select(a => new { a.AgentId, a.DisplayName })
            .ToListAsync(cancellationToken);
        references.AddRange(agents.Select(a => new MibSetReference("agent", a.AgentId, a.DisplayName)));

        var points = await db.SnmpPointConfigs.AsNoTracking()
            .Include(p => p.AgentConfig)
            .Where(p => p.MibSetIdUsedForMapping == mibSetId)
            .OrderBy(p => p.SourcePath)
            .Select(p => new { p.PointName, p.SourcePath, AgentId = p.AgentConfig == null ? "" : p.AgentConfig.AgentId })
            .ToListAsync(cancellationToken);
        references.AddRange(points.Select(p => new MibSetReference("point", p.PointName, $"{p.AgentId} / {p.SourcePath}")));

        return references;
    }

    public async Task<MibFile> UploadMibFileAsync(
        int mibSetId,
        string sourceFileName,
        Stream content,
        CancellationToken cancellationToken = default)
    {
        var set = await db.MibSets.FirstAsync(s => s.Id == mibSetId, cancellationToken);

        var fileName = NormalizeFileName(sourceFileName, "uploaded-file");

        await using var memory = new MemoryStream();
        await content.CopyToAsync(memory, cancellationToken);
        var bytes = memory.ToArray();
        if (bytes.Length == 0)
        {
            throw new InvalidOperationException("Uploaded MIB file is empty.");
        }

        var text = Encoding.UTF8.GetString(bytes);
        var hash = Sha256(bytes);
        var storedPath = BuildStoredPath(mibSetId, hash, fileName);
        Directory.CreateDirectory(Path.GetDirectoryName(storedPath)!);
        await File.WriteAllBytesAsync(storedPath, bytes, cancellationToken);

        var parsed = ParseMibText(
            mibSetId,
            set.Name,
            new MibParseSource(null, fileName, storedPath, IsDefault: false, text));
        var file = await db.MibFiles.FirstOrDefaultAsync(
            f => f.MibSetId == mibSetId && f.FileName == fileName,
            cancellationToken);
        var previousStoredPath = file?.StoredPath;
        if (file is null)
        {
            file = new MibFile { MibSetId = mibSetId, FileName = fileName };
            db.MibFiles.Add(file);
        }

        file.StoredPath = storedPath;
        file.RawContent = null;
        file.Hash = hash;
        file.ModuleName = parsed.ModuleName;
        file.ModuleIdentityOid = parsed.ModuleIdentityOid;
        file.ValidationStatus = parsed.Errors.Count > 0
            ? MibFileValidationStatuses.Failed
            : MibFileValidationStatuses.Parsed;
        file.ErrorMessage = parsed.Errors.Count > 0
            ? string.Join(Environment.NewLine, parsed.Errors.Take(20))
            : null;
        set.Status = MibSetStatuses.SnapshotStale;

        await db.SaveChangesAsync(cancellationToken);
        DeleteOldStorageFile(previousStoredPath, storedPath);
        runtime.SetMib(RuntimeSubsystemStatus.Normal, $"Stored MIB file {file.FileName} in set {set.Name}.");
        return file;
    }

    public async Task<string> ReadFileContentAsync(int mibSetId, int mibFileId, CancellationToken cancellationToken = default)
    {
        var file = await db.MibFiles.AsNoTracking()
            .FirstAsync(f => f.Id == mibFileId && f.MibSetId == mibSetId, cancellationToken);
        return await ReadStoredTextAsync(file, cancellationToken);
    }

    public async Task DeleteFileAsync(int mibSetId, int mibFileId, CancellationToken cancellationToken = default)
    {
        var set = await db.MibSets.FirstAsync(s => s.Id == mibSetId, cancellationToken);

        var file = await db.MibFiles.FirstOrDefaultAsync(
            f => f.Id == mibFileId && f.MibSetId == mibSetId,
            cancellationToken);
        if (file is null)
        {
            return;
        }

        DeleteStoredFile(file.StoredPath);
        db.MibFiles.Remove(file);
        set.Status = MibSetStatuses.SnapshotStale;
        await db.SaveChangesAsync(cancellationToken);
        runtime.SetMib(RuntimeSubsystemStatus.Normal, $"Deleted MIB file {file.FileName} from set {set.Name}.");
    }

    public async Task<MibSetValidationResult> ValidateAsync(int mibSetId, CancellationToken cancellationToken = default)
    {
        var set = await db.MibSets.FirstAsync(s => s.Id == mibSetId, cancellationToken);
        await db.MibSetValidationIssues
            .Where(i => i.MibSetId == mibSetId)
            .ExecuteDeleteAsync(cancellationToken);

        var parsedFiles = await LoadAndParseStoredFilesAsync(mibSetId, set.Name, cancellationToken);
        var nodes = parsedFiles.SelectMany(f => f.Nodes).ToList();
        var userParsedFiles = parsedFiles.Where(f => !f.IsDefault).ToList();
        var userNodes = userParsedFiles.SelectMany(f => f.Nodes).ToList();
        var issues = new List<MibSetValidationIssue>();

        AddFileIssues(mibSetId, parsedFiles, issues);
        AddEmptySetIssue(mibSetId, parsedFiles, issues);
        AddDuplicateModuleIssues(mibSetId, userParsedFiles, issues);
        AddSymbolIssues(mibSetId, userNodes, issues);
        AddOidIssues(mibSetId, userNodes, issues);
        AddImportDependencyIssues(mibSetId, parsedFiles, issues);
        await AddNetSnmpTranslateIssuesAsync(mibSetId, userNodes, StorageDirectories(parsedFiles), issues, cancellationToken);

        if (issues.Count == 0)
        {
            issues.Add(new MibSetValidationIssue
            {
                MibSetId = mibSetId,
                Severity = MibValidationSeverities.Info,
                Code = "validation_passed",
                Message = "MIB set validation completed without conflicts."
            });
        }

        var hasErrors = issues.Any(i => i.Severity == MibValidationSeverities.Error);
        foreach (var parsed in parsedFiles)
        {
            UpdateFileValidationState(parsed);
        }

        db.MibSetValidationIssues.AddRange(issues);
        if (hasErrors)
        {
            set.Status = PreserveStaleOrDraft(set.Status);
        }

        await db.SaveChangesAsync(cancellationToken);
        runtime.SetMib(
            hasErrors ? RuntimeSubsystemStatus.Degraded : RuntimeSubsystemStatus.Normal,
            hasErrors
                ? $"MIB set {set.Name} has validation errors."
                : $"MIB set {set.Name} passed validation.");

        return new MibSetValidationResult(
            issues.Count,
            issues.Count(i => i.Severity == MibValidationSeverities.Error),
            issues.Select(i => i.Message).Take(20).ToList());
    }

    public async Task<MibSetSnapshotRefreshResult> ValidateAndUpdateSnapshotAsync(
        int mibSetId,
        CancellationToken cancellationToken = default)
    {
        var validation = await ValidateAsync(mibSetId, cancellationToken);
        if (validation.ErrorCount > 0)
        {
            return new MibSetSnapshotRefreshResult(false, 0, validation.IssueCount, validation.ErrorCount, validation.Messages);
        }

        var set = await db.MibSets.FirstAsync(s => s.Id == mibSetId, cancellationToken);
        var parsedFiles = await LoadAndParseStoredFilesAsync(mibSetId, set.Name, cancellationToken);
        var parseErrors = parsedFiles.SelectMany(f => f.Errors).ToList();
        if (parseErrors.Count > 0)
        {
            return new MibSetSnapshotRefreshResult(false, 0, validation.IssueCount, parseErrors.Count, parseErrors.Take(20).ToList());
        }

        var nodes = parsedFiles.SelectMany(f => f.Nodes).ToList();
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        await db.MibNodes
            .Where(n => n.MibSetId == mibSetId)
            .ExecuteDeleteAsync(cancellationToken);

        db.MibNodes.AddRange(nodes);
        foreach (var parsed in parsedFiles)
        {
            if (parsed.File is null)
            {
                continue;
            }

            parsed.File.ValidationStatus = MibFileValidationStatuses.Validated;
            parsed.File.ErrorMessage = null;
        }

        set.Status = MibSetStatuses.Available;

        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);

        runtime.SetMib(RuntimeSubsystemStatus.Normal, $"Updated MIB snapshot for set {set.Name} with {nodes.Count} node(s).");
        return new MibSetSnapshotRefreshResult(true, nodes.Count, validation.IssueCount, validation.ErrorCount, validation.Messages);
    }

    private async Task<List<ParsedMibFile>> LoadAndParseStoredFilesAsync(
        int mibSetId,
        string versionName,
        CancellationToken cancellationToken)
    {
        var root = DefaultMibRoot();
        var sources = new List<MibParseSource>();
        var readFailures = new List<ParsedMibFile>();
        foreach (var path in EnumerateDefaultMibFilePaths(root))
        {
            var relativePath = ToDefaultRelativePath(root, path);
            try
            {
                var content = await File.ReadAllTextAsync(path, Encoding.UTF8, cancellationToken);
                sources.Add(new MibParseSource(
                    null,
                    relativePath,
                    path,
                    IsDefault: true,
                    content));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                readFailures.Add(new ParsedMibFile(
                    null,
                    relativePath,
                    path,
                    IsDefault: true,
                    "",
                    null,
                    null,
                    [],
                    [],
                    [$"Base MIB '{relativePath}': {ex.Message}"],
                    []));
            }
        }

        var files = await db.MibFiles
            .Where(f => f.MibSetId == mibSetId)
            .OrderBy(f => f.FileName)
            .ToListAsync(cancellationToken);

        foreach (var file in files)
        {
            try
            {
                var content = await ReadStoredTextAsync(file, cancellationToken);
                sources.Add(new MibParseSource(
                    file,
                    file.FileName,
                    file.StoredPath,
                    IsDefault: false,
                    content));
            }
            catch (Exception ex)
            {
                readFailures.Add(new ParsedMibFile(
                    file,
                    file.FileName,
                    file.StoredPath,
                    IsDefault: false,
                    "",
                    null,
                    null,
                    [],
                    [],
                    [$"{file.FileName}: {ex.Message}"],
                    []));
            }
        }

        var parsedFiles = ParseMibSources(mibSetId, versionName, sources);
        parsedFiles.AddRange(readFailures);
        return parsedFiles;
    }

    private List<ParsedMibFile> ParseMibSources(
        int mibSetId,
        string versionName,
        IReadOnlyList<MibParseSource> sources)
    {
        var symbols = new Dictionary<string, string>(BuiltInOidRoots, StringComparer.OrdinalIgnoreCase);
        var parsedFiles = new List<ParsedMibFile>();

        var maxPasses = Math.Max(4, Math.Min(16, sources.Count + 1));
        for (var pass = 0; pass < maxPasses; pass++)
        {
            parsedFiles = [];
            var learnedThisPass = 0;
            foreach (var source in sources)
            {
                var parsed = ParseMibText(mibSetId, versionName, source, symbols);
                parsedFiles.Add(parsed);

                foreach (var node in parsed.Nodes)
                {
                    if (string.IsNullOrWhiteSpace(node.SymbolicName)
                        || symbols.ContainsKey(node.SymbolicName))
                    {
                        continue;
                    }

                    symbols[node.SymbolicName] = node.NumericOid;
                    learnedThisPass++;
                }
            }

            if (learnedThisPass == 0)
            {
                break;
            }
        }

        return parsedFiles;
    }

    private ParsedMibFile ParseMibText(
        int mibSetId,
        string versionName,
        MibParseSource source,
        IReadOnlyDictionary<string, string>? externalSymbols = null)
    {
        var errors = new List<string>();
        var warnings = new List<string>();
        var content = source.Content;
        var text = CommentPattern.Replace(content, "");
        var moduleName = InferModuleName(text);
        if (string.IsNullOrWhiteSpace(moduleName))
        {
            errors.Add($"{source.DisplayName}: MIB module header was not found.");
        }

        var definitions = MibObjectPattern.Matches(text)
            .Select(match => new MibDefinition(
                match.Groups["symbol"].Value,
                match.Groups["kind"].Value,
                match.Groups["body"].Value,
                match.Groups["assignment"].Value))
            .ToList();

        var symbolOids = externalSymbols is null
            ? new Dictionary<string, string>(BuiltInOidRoots, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(externalSymbols, StringComparer.OrdinalIgnoreCase);
        var pending = definitions.ToList();
        var nodes = new List<MibNode>();
        string? moduleIdentityOid = null;

        while (pending.Count > 0)
        {
            var resolvedThisPass = 0;
            foreach (var definition in pending.ToList())
            {
                var assignment = ParseAssignment(definition.Assignment);
                if (assignment is null)
                {
                    pending.Remove(definition);
                    warnings.Add($"{definition.Symbol}: OID assignment could not be parsed.");
                    continue;
                }

                var parentOid = assignment.ParentOid;
                if (parentOid is null && !symbolOids.TryGetValue(assignment.ParentSymbol ?? "", out parentOid))
                {
                    continue;
                }

                var numericOid = paths.NormalizeNumericOid($"{parentOid}.{assignment.SubId}");
                symbolOids[definition.Symbol] = numericOid;
                if (definition.Kind.Equals("MODULE-IDENTITY", StringComparison.OrdinalIgnoreCase))
                {
                    moduleIdentityOid = numericOid;
                }

                nodes.Add(new MibNode
                {
                    MibSetId = mibSetId,
                    MibFileId = source.File?.Id,
                    VersionName = versionName,
                    NumericOid = numericOid,
                    SymbolicName = definition.Symbol,
                    ModuleName = moduleName,
                    Syntax = ExtractSingleLine(SyntaxPattern, definition.Body),
                    Access = ExtractSingleLine(AccessPattern, definition.Body),
                    Description = ExtractDescription(definition.Body),
                    Active = false
                });

                pending.Remove(definition);
                resolvedThisPass++;
            }

            if (resolvedThisPass == 0)
            {
                foreach (var definition in pending)
                {
                    var assignment = ParseAssignment(definition.Assignment);
                    warnings.Add(assignment?.ParentSymbol is null
                        ? $"{definition.Symbol}: OID assignment could not be resolved."
                        : $"{definition.Symbol}: OID parent '{assignment.ParentSymbol}' could not be resolved.");
                }
                break;
            }
        }

        var imports = ImportModulePattern.Matches(text)
            .Select(match => match.Groups["module"].Value)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new ParsedMibFile(
            source.File,
            source.DisplayName,
            source.SourcePath,
            source.IsDefault,
            content,
            moduleName,
            moduleIdentityOid,
            imports,
            nodes,
            errors,
            warnings);
    }

    private static OidAssignment? ParseAssignment(string assignment)
    {
        var tokens = AssignmentTokenPattern.Matches(assignment)
            .Select(match =>
            {
                var name = match.Groups["name"].Success ? match.Groups["name"].Value : null;
                var number = match.Groups["number"].Success ? int.Parse(match.Groups["number"].Value) : (int?)null;
                var oid = match.Groups["oid"].Success ? match.Groups["oid"].Value.TrimStart('.') : null;
                return new AssignmentToken(name, number, oid);
            })
            .ToList();

        if (tokens.Count < 2)
        {
            return null;
        }

        var last = tokens[^1];
        var subId = last.Number;
        if (subId is null)
        {
            return null;
        }

        var parent = tokens[^2];
        if (!string.IsNullOrWhiteSpace(parent.Oid))
        {
            return new OidAssignment(parent.Oid, null, subId.Value);
        }

        if (!string.IsNullOrWhiteSpace(parent.Name))
        {
            return new OidAssignment(null, parent.Name, subId.Value);
        }

        if (parent.Number is not null)
        {
            return new OidAssignment(parent.Number.Value.ToString(), null, subId.Value);
        }

        return null;
    }

    private static void AddFileIssues(int mibSetId, IReadOnlyList<ParsedMibFile> parsedFiles, List<MibSetValidationIssue> issues)
    {
        foreach (var parsed in parsedFiles)
        {
            foreach (var error in parsed.Errors)
            {
                issues.Add(new MibSetValidationIssue
                {
                    MibSetId = mibSetId,
                    Severity = MibValidationSeverities.Error,
                    Code = "mib_file_error",
                    ModuleName = parsed.ModuleName,
                    Message = error
                });
            }

            foreach (var warning in parsed.Warnings)
            {
                if (parsed.IsDefault)
                {
                    continue;
                }

                issues.Add(new MibSetValidationIssue
                {
                    MibSetId = mibSetId,
                    Severity = MibValidationSeverities.Warning,
                    Code = "mib_file_warning",
                    ModuleName = parsed.ModuleName,
                    Message = $"{parsed.DisplayName}: {warning}"
                });
            }
        }
    }

    private static void AddEmptySetIssue(int mibSetId, IReadOnlyList<ParsedMibFile> parsedFiles, List<MibSetValidationIssue> issues)
    {
        if (parsedFiles.Count > 0)
        {
            return;
        }

        issues.Add(new MibSetValidationIssue
        {
            MibSetId = mibSetId,
            Severity = MibValidationSeverities.Warning,
            Code = "no_mib_files",
            Message = "No MIB files are stored in this set."
        });
    }

    private static void AddDuplicateModuleIssues(int mibSetId, IReadOnlyList<ParsedMibFile> parsedFiles, List<MibSetValidationIssue> issues)
    {
        foreach (var group in parsedFiles
            .Where(f => !string.IsNullOrWhiteSpace(f.ModuleName))
            .GroupBy(f => f.ModuleName!, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1))
        {
            issues.Add(new MibSetValidationIssue
            {
                MibSetId = mibSetId,
                Severity = MibValidationSeverities.Warning,
                Code = "duplicate_module",
                ModuleName = group.Key,
                Message = $"Module '{group.Key}' appears in {group.Count()} file(s) in this set."
            });
        }
    }

    private static void AddSymbolIssues(int mibSetId, IReadOnlyList<MibNode> nodes, List<MibSetValidationIssue> issues)
    {
        foreach (var group in nodes
            .Where(n => !string.IsNullOrWhiteSpace(n.SymbolicName))
            .GroupBy(n => n.SymbolicName!, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1))
        {
            var distinctOids = group.Select(n => n.NumericOid).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var first = group.First();
            issues.Add(new MibSetValidationIssue
            {
                MibSetId = mibSetId,
                Severity = distinctOids.Count > 1 ? MibValidationSeverities.Error : MibValidationSeverities.Warning,
                Code = distinctOids.Count > 1 ? "symbol_oid_conflict" : "duplicate_symbol",
                ModuleName = first.ModuleName,
                NumericOid = first.NumericOid,
                SymbolicName = group.Key,
                Message = distinctOids.Count > 1
                    ? $"Symbol '{group.Key}' maps to multiple OIDs in this set: {string.Join(", ", distinctOids.Take(5))}."
                    : $"Symbol '{group.Key}' appears {group.Count()} time(s) for OID {distinctOids[0]}."
            });
        }
    }

    private static void AddOidIssues(int mibSetId, IReadOnlyList<MibNode> nodes, List<MibSetValidationIssue> issues)
    {
        foreach (var group in nodes
            .GroupBy(n => n.NumericOid, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1))
        {
            var labels = group
                .Select(n => n.SymbolicName)
                .Where(label => !string.IsNullOrWhiteSpace(label))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            var first = group.First();
            issues.Add(new MibSetValidationIssue
            {
                MibSetId = mibSetId,
                Severity = labels.Count > 1 ? MibValidationSeverities.Error : MibValidationSeverities.Warning,
                Code = labels.Count > 1 ? "oid_label_conflict" : "duplicate_oid",
                ModuleName = first.ModuleName,
                NumericOid = group.Key,
                SymbolicName = first.SymbolicName,
                Message = labels.Count > 1
                    ? $"OID {group.Key} maps to multiple labels in this set: {string.Join(", ", labels.Take(5))}."
                    : $"OID {group.Key} appears {group.Count()} time(s) in this set."
            });
        }
    }

    private static void AddImportDependencyIssues(
        int mibSetId,
        IReadOnlyList<ParsedMibFile> parsedFiles,
        List<MibSetValidationIssue> issues)
    {
        var localModules = parsedFiles.Select(f => f.ModuleName)
            .Where(m => !string.IsNullOrWhiteSpace(m))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var wellKnownModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "SNMPv2-SMI",
            "SNMPv2-TC",
            "SNMPv2-CONF",
            "SNMPv2-MIB",
            "RFC1213-MIB",
            "IF-MIB"
        };

        foreach (var parsed in parsedFiles.Where(f => !f.IsDefault))
        {
            foreach (var importedModule in parsed.Imports)
            {
                if (localModules.Contains(importedModule) || wellKnownModules.Contains(importedModule))
                {
                    continue;
                }

                issues.Add(new MibSetValidationIssue
                {
                    MibSetId = mibSetId,
                    Severity = MibValidationSeverities.Warning,
                    Code = "missing_dependency",
                    ModuleName = parsed.ModuleName,
                    Message = $"File '{parsed.DisplayName}' imports '{importedModule}', but that module is not present in the snapshot input."
                });
            }
        }
    }

    private async Task AddNetSnmpTranslateIssuesAsync(
        int mibSetId,
        IReadOnlyList<MibNode> nodes,
        IReadOnlyList<string> mibDirectories,
        List<MibSetValidationIssue> issues,
        CancellationToken cancellationToken)
    {
        if (snmp is null || mibDirectories.Count == 0)
        {
            return;
        }

        var symbols = nodes
            .Select(n => n.SymbolicName)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(25)
            .ToList();
        foreach (var symbol in symbols)
        {
            try
            {
                var result = await snmp.TranslateAsync(symbol!, mibDirectories, loadAllMibs: true, cancellationToken);
                if (result.Success)
                {
                    continue;
                }

                issues.Add(new MibSetValidationIssue
                {
                    MibSetId = mibSetId,
                    Severity = MibValidationSeverities.Warning,
                    Code = "net_snmp_translate_error",
                    SymbolicName = symbol,
                    Message = $"Net-SNMP could not translate '{symbol}': {result.ErrorMessage ?? result.ErrorCode ?? "translate failed"}"
                });
            }
            catch (Exception ex)
            {
                issues.Add(new MibSetValidationIssue
                {
                    MibSetId = mibSetId,
                    Severity = MibValidationSeverities.Warning,
                    Code = "net_snmp_translate_error",
                    SymbolicName = symbol,
                    Message = $"Net-SNMP translate check failed for '{symbol}': {ex.Message}"
                });
                return;
            }
        }
    }

    private void UpdateFileValidationState(ParsedMibFile parsed)
    {
        if (parsed.File is null)
        {
            return;
        }

        parsed.File.ModuleName = parsed.ModuleName;
        parsed.File.ModuleIdentityOid = parsed.ModuleIdentityOid;
        if (parsed.Errors.Count > 0)
        {
            parsed.File.ValidationStatus = MibFileValidationStatuses.Failed;
            parsed.File.ErrorMessage = string.Join(Environment.NewLine, parsed.Errors.Take(20));
            return;
        }

        parsed.File.ValidationStatus = MibFileValidationStatuses.Parsed;
        parsed.File.ErrorMessage = parsed.Warnings.Count > 0
            ? string.Join(Environment.NewLine, parsed.Warnings.Take(20))
            : null;
    }

    private async Task<string> ReadStoredTextAsync(MibFile file, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(file.StoredPath))
        {
            throw new InvalidOperationException("Stored path is missing.");
        }

        var path = ResolveStoredPath(file.StoredPath);
        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Stored MIB file was not found.", path);
        }

        return await File.ReadAllTextAsync(path, Encoding.UTF8, cancellationToken);
    }

    private string BuildStoredPath(int mibSetId, string hash, string fileName)
    {
        var root = MibStorageRoot();
        return Path.Combine(root, mibSetId.ToString(), hash, fileName);
    }

    private string MibStorageRoot() =>
        Path.GetFullPath(netSnmpOptions.Value.MibDirectory);

    private string DefaultMibRoot()
    {
        var configured = netSnmpOptions.Value.DefaultMibDirectory;
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return Path.GetFullPath(configured);
        }

        var contentRoot = hostEnvironment?.ContentRootPath;
        return Path.GetFullPath(string.IsNullOrWhiteSpace(contentRoot)
            ? Path.Combine(AppContext.BaseDirectory, "Resources", "DefaultMibs")
            : Path.Combine(contentRoot, "Resources", "DefaultMibs"));
    }

    private static IReadOnlyList<string> EnumerateDefaultMibFilePaths(string root)
    {
        if (!Directory.Exists(root))
        {
            return [];
        }

        return Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .OrderBy(path => ToDefaultRelativePath(root, path), StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private string ResolveDefaultMibPath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) || Path.IsPathRooted(relativePath))
        {
            throw new InvalidOperationException("Default MIB file path is invalid.");
        }

        var root = DefaultMibRoot();
        var normalizedRelativePath = relativePath
            .Replace('/', Path.DirectorySeparatorChar)
            .Replace('\\', Path.DirectorySeparatorChar);
        var fullPath = Path.GetFullPath(Path.Combine(root, normalizedRelativePath));
        var rootWithSeparator = Path.GetFullPath(root)
                                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                                + Path.DirectorySeparatorChar;
        if (!fullPath.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Default MIB path is outside the configured default MIB directory.");
        }

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("Default MIB file was not found.", fullPath);
        }

        return fullPath;
    }

    private static string ToDefaultRelativePath(string root, string path) =>
        Path.GetRelativePath(root, path)
            .Replace(Path.DirectorySeparatorChar, '/')
            .Replace(Path.AltDirectorySeparatorChar, '/');

    private string ResolveStoredPath(string storedPath)
    {
        var fullPath = Path.GetFullPath(storedPath);
        var root = MibStorageRoot().TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                   + Path.DirectorySeparatorChar;
        if (!fullPath.StartsWith(root, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Stored MIB path is outside the configured MIB storage directory.");
        }

        return fullPath;
    }

    private static IReadOnlyList<string> StorageDirectories(IReadOnlyList<ParsedMibFile> parsedFiles) =>
        parsedFiles
            .Select(f => string.IsNullOrWhiteSpace(f.SourcePath) ? null : Path.GetDirectoryName(f.SourcePath))
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Cast<string>()
            .ToList();

    private void DeleteOldStorageFile(string? previousPath, string currentPath)
    {
        if (string.IsNullOrWhiteSpace(previousPath)
            || string.Equals(Path.GetFullPath(previousPath), Path.GetFullPath(currentPath), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        DeleteStoredFile(previousPath);
    }

    private void DeleteStoredFile(string? storedPath)
    {
        if (string.IsNullOrWhiteSpace(storedPath))
        {
            return;
        }

        var path = ResolveStoredPath(storedPath);
        if (File.Exists(path))
        {
            File.Delete(path);
        }

        var root = MibStorageRoot().TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var directory = Path.GetDirectoryName(path);
        while (!string.IsNullOrWhiteSpace(directory)
               && !string.Equals(directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), root, StringComparison.OrdinalIgnoreCase)
               && Directory.Exists(directory)
               && !Directory.EnumerateFileSystemEntries(directory).Any())
        {
            Directory.Delete(directory);
            directory = Path.GetDirectoryName(directory);
        }
    }

    private static void ValidateSet(MibSet set)
    {
        if (string.IsNullOrWhiteSpace(set.Name))
        {
            throw new InvalidOperationException("MIB set name is required.");
        }
    }

    private static string NormalizeSetStatus(string? status)
    {
        var normalized = status?.ToLowerInvariant();
        return normalized switch
        {
            MibSetStatuses.Draft => MibSetStatuses.Draft,
            MibSetStatuses.SnapshotStale => MibSetStatuses.SnapshotStale,
            MibSetStatuses.Available => MibSetStatuses.Available,
            "validated" => MibSetStatuses.SnapshotStale,
            _ => MibSetStatuses.Draft
        };
    }

    private static string PreserveStaleOrDraft(string status) =>
        status == MibSetStatuses.SnapshotStale ? MibSetStatuses.SnapshotStale : MibSetStatuses.Draft;

    private static string NormalizeFileName(string? value, string fallback)
    {
        var fileName = string.IsNullOrWhiteSpace(value) ? fallback : Path.GetFileName(value.Trim());
        if (string.IsNullOrWhiteSpace(fileName))
        {
            fileName = fallback;
        }

        foreach (var invalid in Path.GetInvalidFileNameChars())
        {
            fileName = fileName.Replace(invalid, '_');
        }

        return fileName;
    }

    private static string? InferModuleName(string content)
    {
        var match = ModuleNamePattern.Match(content);
        return match.Success ? match.Groups["module"].Value : null;
    }

    private static string? ExtractSingleLine(Regex pattern, string body)
    {
        var match = pattern.Match(body);
        return match.Success ? match.Groups["value"].Value.Trim() : null;
    }

    private static string? ExtractDescription(string body)
    {
        var match = DescriptionPattern.Match(body);
        return match.Success ? match.Groups["value"].Value.Replace("\"\"", "\"", StringComparison.Ordinal).Trim() : null;
    }

    private static string Sha256(byte[] content)
    {
        var hash = SHA256.HashData(content);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private sealed record MibParseSource(
        MibFile? File,
        string DisplayName,
        string? SourcePath,
        bool IsDefault,
        string Content);

    private sealed record ParsedMibFile(
        MibFile? File,
        string DisplayName,
        string? SourcePath,
        bool IsDefault,
        string Content,
        string? ModuleName,
        string? ModuleIdentityOid,
        IReadOnlyList<string> Imports,
        List<MibNode> Nodes,
        List<string> Errors,
        List<string> Warnings);

    private sealed record MibDefinition(string Symbol, string Kind, string Body, string Assignment);

    private sealed record AssignmentToken(string? Name, int? Number, string? Oid);

    private sealed record OidAssignment(string? ParentOid, string? ParentSymbol, int SubId);
}
