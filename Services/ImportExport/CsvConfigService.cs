using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Paths;
using Ptlk.RedisSnmp.Services.Redis;

namespace Ptlk.RedisSnmp.Services.ImportExport;

public sealed record CsvImportResult(int ImportedRows, IReadOnlyList<string> Errors);

public sealed class CsvConfigService(
    AppDbContext db,
    IOptions<ImportExportOptions> options,
    SnmpSourcePathService paths,
    RedisMappingValidationService mappingValidation)
{
    private const string Redacted = "__REDACTED__";
    private static readonly string[] ExportHeaders =
    [
        "kind",
        "name",
        "version",
        "status",
        "agent_id",
        "display_name",
        "host",
        "port",
        "snmp_version",
        "credential_name",
        "preferred_mib_set",
        "security_name",
        "security_level",
        "auth_protocol",
        "priv_protocol",
        "protected_community",
        "protected_read_community",
        "protected_write_community",
        "protected_auth_password",
        "protected_priv_password",
        "numeric_oid",
        "value_type",
        "access",
        "mib_label",
        "mib_module",
        "mib_syntax",
        "mib_access",
        "mib_description",
        "mapping_source_path",
        "mapping_redis_key",
        "trap_oid",
        "description",
        "mib_set"
    ];

    public async Task<Stream> ExportAsync(CancellationToken cancellationToken = default)
    {
        var builder = new StringBuilder();
        builder.AppendLine(Csv(ExportHeaders));

        foreach (var set in await db.MibSets.AsNoTracking().OrderBy(s => s.Name).ToListAsync(cancellationToken))
        {
            var row = NewExportRow("mib_set");
            Set(row, "name", set.Name);
            Set(row, "mib_set", set.Name);
            Set(row, "status", set.Status);
            Set(row, "description", set.Description ?? "");
            builder.AppendLine(Csv(row));
        }

        foreach (var credential in await db.SnmpCredentialConfigs.AsNoTracking().OrderBy(c => c.Name).ToListAsync(cancellationToken))
        {
            var row = NewExportRow("credential");
            Set(row, "name", credential.Name);
            Set(row, "version", credential.Version);
            Set(row, "security_name", credential.SecurityName ?? "");
            Set(row, "security_level", credential.SecurityLevel ?? "");
            Set(row, "auth_protocol", credential.AuthProtocol ?? "");
            Set(row, "priv_protocol", credential.PrivProtocol ?? "");
            Set(row, "protected_community", credential.ProtectedCommunity ?? "");
            Set(row, "protected_read_community", credential.ProtectedReadCommunity ?? "");
            Set(row, "protected_write_community", credential.ProtectedWriteCommunity ?? "");
            Set(row, "protected_auth_password", credential.ProtectedAuthPassword ?? "");
            Set(row, "protected_priv_password", credential.ProtectedPrivPassword ?? "");
            Set(row, "description", credential.Description ?? "");
            builder.AppendLine(Csv(row));
        }

        foreach (var agent in await db.SnmpAgentConfigs
                     .AsNoTracking()
                     .Include(a => a.CredentialConfig)
                     .Include(a => a.PreferredMibSet)
                     .OrderBy(a => a.AgentId)
                     .ToListAsync(cancellationToken))
        {
            var row = NewExportRow("agent");
            Set(row, "agent_id", agent.AgentId);
            Set(row, "display_name", agent.DisplayName);
            Set(row, "host", agent.Host);
            Set(row, "port", agent.Port.ToString());
            Set(row, "snmp_version", agent.SnmpVersion);
            Set(row, "credential_name", agent.CredentialConfig?.Name ?? "");
            Set(row, "preferred_mib_set", agent.PreferredMibSet?.Name ?? "");
            Set(row, "description", agent.Description ?? "");
            builder.AppendLine(Csv(row));
        }

        foreach (var point in await db.SnmpPointConfigs.AsNoTracking().Include(p => p.AgentConfig).OrderBy(p => p.SourcePath).ToListAsync(cancellationToken))
        {
            var row = NewExportRow("point");
            Set(row, "agent_id", point.AgentConfig?.AgentId ?? "");
            Set(row, "numeric_oid", point.NumericOid);
            Set(row, "value_type", point.ValueType);
            Set(row, "access", point.Access);
            Set(row, "mib_label", point.MibLabel ?? "");
            Set(row, "mib_module", point.MibModule ?? "");
            Set(row, "mib_syntax", point.MibSyntax ?? "");
            Set(row, "mib_access", point.MibAccess ?? "");
            Set(row, "mib_description", point.MibDescription ?? "");
            Set(row, "description", point.Description ?? "");
            builder.AppendLine(Csv(row));
        }

        foreach (var rule in await db.SnmpTrapRuleConfigs.AsNoTracking().OrderBy(r => r.AgentId).ThenBy(r => r.TrapOid).ToListAsync(cancellationToken))
        {
            var row = NewExportRow("trap_rule");
            Set(row, "agent_id", rule.AgentId);
            Set(row, "display_name", rule.DisplayName);
            Set(row, "trap_oid", rule.TrapOid);
            Set(row, "description", rule.Description ?? "");
            builder.AppendLine(Csv(row));
        }

        foreach (var mapping in await db.RedisMappings.AsNoTracking().OrderBy(m => m.SourcePath).ToListAsync(cancellationToken))
        {
            var row = NewExportRow("mapping");
            Set(row, "mapping_source_path", mapping.SourcePath);
            Set(row, "mapping_redis_key", mapping.RedisKey);
            builder.AppendLine(Csv(row));
        }

        return new MemoryStream(Encoding.UTF8.GetBytes(builder.ToString()));
    }

    public async Task<CsvImportResult> ImportAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        if (stream.CanSeek && stream.Length > options.Value.SingleCsvLimitBytes)
        {
            return new CsvImportResult(0, [$"CSV size exceeds {options.Value.SingleCsvLimitBytes} bytes."]);
        }

        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        var content = await reader.ReadToEndAsync(cancellationToken);
        var lines = content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        if (lines.Length <= 1)
        {
            return new CsvImportResult(0, []);
        }

        var headers = SplitCsv(lines[0]);
        var rows = new List<ImportRow>();
        for (var i = 1; i < lines.Length; i++)
        {
            if (string.IsNullOrWhiteSpace(lines[i]))
            {
                continue;
            }

            rows.Add(new ImportRow(i + 1, headers, SplitCsv(lines[i])));
        }

        var errors = new List<string>();
        var imported = 0;

        await using var tx = await db.Database.BeginTransactionAsync(cancellationToken);
        try
        {
            imported += await ApplyMibSetsAsync(rows.Where(IsKind("mib_set")), errors, cancellationToken);
            await db.SaveChangesAsync(cancellationToken);

            imported += await ApplyCredentialsAsync(rows.Where(IsKind("credential")), errors, cancellationToken);
            await db.SaveChangesAsync(cancellationToken);

            imported += await ApplyAgentsAsync(rows.Where(IsKind("agent")), errors, cancellationToken);
            await db.SaveChangesAsync(cancellationToken);

            imported += await ApplyPointsAsync(rows.Where(IsKind("point")), errors, cancellationToken);
            imported += await ApplyTrapRulesAsync(rows.Where(IsKind("trap_rule")), errors, cancellationToken);
            await db.SaveChangesAsync(cancellationToken);

            if (errors.Count == 0)
            {
                imported += await ApplyMappingsAsync(rows.Where(IsKind("mapping")), errors, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            errors.Add(ex.Message);
        }

        if (errors.Count > 0)
        {
            await tx.RollbackAsync(cancellationToken);
            db.ChangeTracker.Clear();
            return new CsvImportResult(0, errors);
        }

        await db.SaveChangesAsync(cancellationToken);
        await tx.CommitAsync(cancellationToken);
        return new CsvImportResult(imported, []);
    }

    private async Task<int> ApplyMibSetsAsync(
        IEnumerable<ImportRow> rows,
        List<string> errors,
        CancellationToken cancellationToken)
    {
        var imported = 0;
        foreach (var row in rows)
        {
            try
            {
                var name = FirstNotBlank(row.Get("mib_set"), row.Get("name"));
                if (string.IsNullOrWhiteSpace(name))
                {
                    throw new InvalidOperationException("MIB set name is required.");
                }

                var set = await db.MibSets.FirstOrDefaultAsync(s => s.Name == name, cancellationToken)
                          ?? db.MibSets.Local.FirstOrDefault(s => s.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                          ?? new MibSet();
                set.Name = name.Trim();
                set.Description = EmptyToNull(row.Get("description"));
                if (!string.IsNullOrWhiteSpace(row.Get("status")))
                {
                    set.Status = row.Get("status").Trim();
                }

                if (set.Id == 0 && db.Entry(set).State == EntityState.Detached)
                {
                    db.MibSets.Add(set);
                }

                imported++;
            }
            catch (Exception ex)
            {
                errors.Add($"Line {row.Line}: {ex.Message}");
            }
        }

        return imported;
    }

    private async Task<int> ApplyCredentialsAsync(
        IEnumerable<ImportRow> rows,
        List<string> errors,
        CancellationToken cancellationToken)
    {
        var imported = 0;
        foreach (var row in rows)
        {
            try
            {
                var name = row.Get("name");
                if (string.IsNullOrWhiteSpace(name))
                {
                    throw new InvalidOperationException("Credential name is required.");
                }

                var credential = await db.SnmpCredentialConfigs.FirstOrDefaultAsync(c => c.Name == name, cancellationToken)
                                 ?? db.SnmpCredentialConfigs.Local.FirstOrDefault(c => c.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                                 ?? new SnmpCredentialConfig();
                credential.Name = name.Trim();
                credential.Version = EmptyDefault(row.Get("version"), SnmpVersions.V2C);
                credential.SecurityName = EmptyToNull(row.Get("security_name"));
                credential.SecurityLevel = EmptyToNull(row.Get("security_level"));
                credential.AuthProtocol = EmptyToNull(row.Get("auth_protocol"));
                credential.PrivProtocol = EmptyToNull(row.Get("priv_protocol"));
                SetProtectedSecretIfPresent(row, "protected_community", value => credential.ProtectedCommunity = value);
                SetProtectedSecretIfPresent(row, "protected_read_community", value => credential.ProtectedReadCommunity = value);
                SetProtectedSecretIfPresent(row, "protected_write_community", value => credential.ProtectedWriteCommunity = value);
                SetProtectedSecretIfPresent(row, "protected_auth_password", value => credential.ProtectedAuthPassword = value);
                SetProtectedSecretIfPresent(row, "protected_priv_password", value => credential.ProtectedPrivPassword = value);
                credential.Description = EmptyToNull(row.Get("description"));

                if (credential.Id == 0 && db.Entry(credential).State == EntityState.Detached)
                {
                    db.SnmpCredentialConfigs.Add(credential);
                }

                imported++;
            }
            catch (Exception ex)
            {
                errors.Add($"Line {row.Line}: {ex.Message}");
            }
        }

        return imported;
    }

    private async Task<int> ApplyAgentsAsync(
        IEnumerable<ImportRow> rows,
        List<string> errors,
        CancellationToken cancellationToken)
    {
        var imported = 0;
        foreach (var row in rows)
        {
            try
            {
                var agentId = row.Get("agent_id");
                if (string.IsNullOrWhiteSpace(agentId))
                {
                    throw new InvalidOperationException("AgentId is required.");
                }

                var host = row.Get("host");
                if (string.IsNullOrWhiteSpace(host))
                {
                    throw new InvalidOperationException("Host is required.");
                }

                var agent = await FindAgentAsync(agentId, cancellationToken) ?? new SnmpAgentConfig();
                agent.AgentId = agentId.Trim();
                agent.DisplayName = EmptyDefault(row.Get("display_name"), agent.AgentId);
                agent.Host = host.Trim();
                agent.Port = int.TryParse(row.Get("port"), out var port) ? port : 161;
                agent.SnmpVersion = EmptyDefault(row.Get("snmp_version"), SnmpVersions.V2C);
                if (row.HasField("credential_name"))
                {
                    agent.CredentialConfigId = await ResolveCredentialConfigIdAsync(row.Get("credential_name"), cancellationToken);
                }
                agent.PreferredMibSetId = await ResolveMibSetIdAsync(row.Get("preferred_mib_set"), cancellationToken);
                agent.Description = EmptyToNull(row.Get("description"));

                if (agent.Id == 0 && db.Entry(agent).State == EntityState.Detached)
                {
                    db.SnmpAgentConfigs.Add(agent);
                }

                imported++;
            }
            catch (Exception ex)
            {
                errors.Add($"Line {row.Line}: {ex.Message}");
            }
        }

        return imported;
    }

    private async Task<int> ApplyPointsAsync(
        IEnumerable<ImportRow> rows,
        List<string> errors,
        CancellationToken cancellationToken)
    {
        var imported = 0;
        foreach (var row in rows)
        {
            try
            {
                var agentId = row.Get("agent_id");
                var agent = await FindAgentAsync(agentId, cancellationToken)
                            ?? throw new InvalidOperationException($"AgentId '{agentId}' was not found.");
                var oid = paths.NormalizeNumericOid(row.Get("numeric_oid"));
                var sourcePath = paths.BuildPointSourcePath(agent.AgentId, oid);

                var point = await db.SnmpPointConfigs.FirstOrDefaultAsync(p => p.SourcePath == sourcePath, cancellationToken)
                            ?? db.SnmpPointConfigs.Local.FirstOrDefault(p => p.SourcePath.Equals(sourcePath, StringComparison.OrdinalIgnoreCase))
                            ?? new SnmpPointConfig();
                point.AgentConfigId = agent.Id;
                point.NumericOid = oid;
                point.SourcePath = sourcePath;
                point.ValueType = EmptyDefault(row.Get("value_type"), SnmpValueTypes.String);
                point.Access = EmptyDefault(row.Get("access"), SnmpAccessModes.ReadOnly);
                point.MibLabel = EmptyToNull(row.Get("mib_label"));
                point.MibModule = EmptyToNull(row.Get("mib_module"));
                point.MibSyntax = EmptyToNull(row.Get("mib_syntax"));
                point.MibAccess = EmptyToNull(row.Get("mib_access"));
                point.MibDescription = EmptyToNull(row.Get("mib_description"));
                point.Description = EmptyToNull(row.Get("description"));

                if (point.Id == 0 && db.Entry(point).State == EntityState.Detached)
                {
                    db.SnmpPointConfigs.Add(point);
                }

                imported++;
            }
            catch (Exception ex)
            {
                errors.Add($"Line {row.Line}: {ex.Message}");
            }
        }

        return imported;
    }

    private async Task<int> ApplyTrapRulesAsync(
        IEnumerable<ImportRow> rows,
        List<string> errors,
        CancellationToken cancellationToken)
    {
        var imported = 0;
        foreach (var row in rows)
        {
            try
            {
                var agentId = row.Get("agent_id");
                var trapOid = paths.NormalizeNumericOid(row.Get("trap_oid"));
                var rule = await db.SnmpTrapRuleConfigs.FirstOrDefaultAsync(
                               r => r.AgentId == agentId && r.TrapOid == trapOid,
                               cancellationToken)
                           ?? db.SnmpTrapRuleConfigs.Local.FirstOrDefault(
                               r => r.AgentId.Equals(agentId, StringComparison.OrdinalIgnoreCase)
                                    && r.TrapOid.Equals(trapOid, StringComparison.OrdinalIgnoreCase))
                           ?? new SnmpTrapRuleConfig();
                rule.AgentId = agentId.Trim();
                rule.TrapOid = trapOid;
                rule.DisplayName = EmptyDefault(row.Get("display_name"), trapOid);
                rule.Description = EmptyToNull(row.Get("description"));

                if (rule.Id == 0 && db.Entry(rule).State == EntityState.Detached)
                {
                    db.SnmpTrapRuleConfigs.Add(rule);
                }

                imported++;
            }
            catch (Exception ex)
            {
                errors.Add($"Line {row.Line}: {ex.Message}");
            }
        }

        return imported;
    }

    private async Task<int> ApplyMappingsAsync(
        IEnumerable<ImportRow> rows,
        List<string> errors,
        CancellationToken cancellationToken)
    {
        var imported = 0;
        foreach (var row in rows)
        {
            try
            {
                var sourcePath = row.Get("mapping_source_path").Trim();
                var redisKey = row.Get("mapping_redis_key").Trim();
                var bySource = await db.RedisMappings.FirstOrDefaultAsync(m => m.SourcePath == sourcePath, cancellationToken);
                var byKey = await db.RedisMappings.FirstOrDefaultAsync(m => m.RedisKey == redisKey, cancellationToken);
                if (bySource is not null && byKey is not null && bySource.Id != byKey.Id)
                {
                    throw new InvalidOperationException($"Mapping '{sourcePath}' conflicts with Redis key '{redisKey}'.");
                }

                var existing = bySource ?? byKey;
                var result = await mappingValidation.ValidateAsync(sourcePath, redisKey, existing?.Id, cancellationToken);
                if (!result.Success)
                {
                    throw new InvalidOperationException(result.Error);
                }

                await mappingValidation.CreateOrUpdateAsync(existing?.Id, sourcePath, redisKey, cancellationToken);
                imported++;
            }
            catch (Exception ex)
            {
                errors.Add($"Line {row.Line}: {ex.Message}");
            }
        }

        return imported;
    }

    private async Task<SnmpAgentConfig?> FindAgentAsync(string agentId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(agentId))
        {
            return null;
        }

        var local = db.SnmpAgentConfigs.Local.FirstOrDefault(a => a.AgentId.Equals(agentId.Trim(), StringComparison.OrdinalIgnoreCase));
        return local ?? await db.SnmpAgentConfigs.FirstOrDefaultAsync(a => a.AgentId == agentId.Trim(), cancellationToken);
    }

    private async Task<int?> ResolveCredentialConfigIdAsync(string credentialName, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(credentialName))
        {
            return null;
        }

        var value = credentialName.Trim();
        var local = db.SnmpCredentialConfigs.Local.FirstOrDefault(c => c.Name.Equals(value, StringComparison.OrdinalIgnoreCase));
        if (local is not null)
        {
            return local.Id;
        }

        var id = await db.SnmpCredentialConfigs
            .AsNoTracking()
            .Where(c => c.Name == value)
            .Select(c => (int?)c.Id)
            .FirstOrDefaultAsync(cancellationToken);
        return id ?? throw new InvalidOperationException($"Credential '{value}' was not found.");
    }

    private async Task<int?> ResolveMibSetIdAsync(string nameOrId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(nameOrId))
        {
            return null;
        }

        var value = nameOrId.Trim();
        if (int.TryParse(value, out var id))
        {
            return id;
        }

        var local = db.MibSets.Local.FirstOrDefault(s => s.Name.Equals(value, StringComparison.OrdinalIgnoreCase));
        if (local is not null && local.Id > 0)
        {
            return local.Id;
        }

        return await db.MibSets
            .AsNoTracking()
            .Where(s => s.Name == value)
            .Select(s => (int?)s.Id)
            .FirstOrDefaultAsync(cancellationToken);
    }

    private static Func<ImportRow, bool> IsKind(string kind) =>
        row => row.Get("kind").Equals(kind, StringComparison.OrdinalIgnoreCase);

    private static string Csv(params string[] values) =>
        string.Join(",", values.Select(value => value.Contains(',') || value.Contains('"') || value.Contains('\n')
            ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\""
            : value));

    private static string[] NewExportRow(string kind)
    {
        var row = new string[ExportHeaders.Length];
        Array.Fill(row, "");
        Set(row, "kind", kind);
        return row;
    }

    private static void Set(string[] row, string name, string value)
    {
        var index = Array.FindIndex(ExportHeaders, header => header.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (index >= 0)
        {
            row[index] = value;
        }
    }

    private static string[] SplitCsv(string line)
    {
        var values = new List<string>();
        var current = new StringBuilder();
        var inQuote = false;
        for (var i = 0; i < line.Length; i++)
        {
            var ch = line[i];
            if (ch == '"')
            {
                if (inQuote && i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else
                {
                    inQuote = !inQuote;
                }
            }
            else if (ch == ',' && !inQuote)
            {
                values.Add(current.ToString());
                current.Clear();
            }
            else
            {
                current.Append(ch);
            }
        }
        values.Add(current.ToString());
        return values.ToArray();
    }

    private static string EmptyDefault(string value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();

    private static string FirstNotBlank(params string[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? "";

    private static string? EmptyToNull(string value) =>
        string.IsNullOrWhiteSpace(value) || value.Equals(Redacted, StringComparison.OrdinalIgnoreCase)
            ? null
            : value.Trim();

    private static void SetProtectedSecretIfPresent(ImportRow row, string name, Action<string> apply)
    {
        if (!row.HasField(name))
        {
            return;
        }

        var value = EmptyToNull(row.Get(name));
        if (value is not null)
        {
            apply(value);
        }
    }

    private sealed class ImportRow(int line, IReadOnlyList<string> headers, IReadOnlyList<string> fields)
    {
        public int Line { get; } = line;

        public bool HasField(string name) =>
            headers.Any(header => header.Equals(name, StringComparison.OrdinalIgnoreCase));

        public string Get(string name)
        {
            var index = Array.FindIndex(headers.ToArray(), header => header.Equals(name, StringComparison.OrdinalIgnoreCase));
            return index >= 0 && index < fields.Count ? fields[index] : "";
        }

    }
}
