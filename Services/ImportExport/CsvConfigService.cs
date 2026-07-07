using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
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
        "agent_id",
        "display_name",
        "host",
        "port",
        "snmp_version",
        "preferred_mib_set",
        "point_name",
        "numeric_oid",
        "value_type",
        "access",
        "mib_set_used",
        "mib_label",
        "mib_module",
        "mib_syntax",
        "mib_access",
        "mib_description",
        "mapping_source_path",
        "mapping_redis_key",
        "trap_oid",
        "description"
    ];

    public async Task<Stream> ExportAsync(CancellationToken cancellationToken = default)
    {
        var builder = new StringBuilder();
        builder.AppendLine(Csv(ExportHeaders));

        foreach (var credential in await db.SnmpCredentialConfigs.AsNoTracking().OrderBy(c => c.Name).ToListAsync(cancellationToken))
        {
            var row = NewExportRow("credential");
            row[1] = credential.Name;
            row[2] = credential.Version;
            row[22] = Redacted;
            builder.AppendLine(Csv(row));
        }

        foreach (var agent in await db.SnmpAgentConfigs.AsNoTracking().Include(a => a.PreferredMibSet).OrderBy(a => a.AgentId).ToListAsync(cancellationToken))
        {
            var row = NewExportRow("agent");
            row[3] = agent.AgentId;
            row[4] = agent.DisplayName;
            row[5] = agent.Host;
            row[6] = agent.Port.ToString();
            row[7] = agent.SnmpVersion;
            row[8] = agent.PreferredMibSet?.Name ?? "";
            row[22] = agent.Description ?? "";
            builder.AppendLine(Csv(row));
        }

        foreach (var point in await db.SnmpPointConfigs.AsNoTracking().Include(p => p.AgentConfig).Include(p => p.MibSetUsedForMapping).OrderBy(p => p.SourcePath).ToListAsync(cancellationToken))
        {
            var row = NewExportRow("point");
            row[3] = point.AgentConfig?.AgentId ?? "";
            row[9] = point.PointName;
            row[10] = point.NumericOid;
            row[11] = point.ValueType;
            row[12] = point.Access;
            row[13] = point.MibSetUsedForMapping?.Name ?? "";
            row[14] = point.MibLabel ?? "";
            row[15] = point.MibModule ?? "";
            row[16] = point.MibSyntax ?? "";
            row[17] = point.MibAccess ?? "";
            row[18] = point.MibDescription ?? "";
            row[22] = point.Description ?? "";
            builder.AppendLine(Csv(row));
        }

        foreach (var rule in await db.SnmpTrapRuleConfigs.AsNoTracking().OrderBy(r => r.AgentId).ThenBy(r => r.TrapOid).ToListAsync(cancellationToken))
        {
            var row = NewExportRow("trap_rule");
            row[3] = rule.AgentId;
            row[4] = rule.DisplayName;
            row[21] = rule.TrapOid;
            row[22] = rule.Description ?? "";
            builder.AppendLine(Csv(row));
        }

        foreach (var mapping in await db.RedisMappings.AsNoTracking().OrderBy(m => m.SourcePath).ToListAsync(cancellationToken))
        {
            var row = NewExportRow("mapping");
            row[19] = mapping.SourcePath;
            row[20] = mapping.RedisKey;
            builder.AppendLine(Csv(row));
        }

        return new MemoryStream(Encoding.UTF8.GetBytes(builder.ToString()));
    }

    public async Task<CsvImportResult> ImportAsync(Stream stream, CancellationToken cancellationToken = default)
    {
        if (stream.Length > options.Value.SingleCsvLimitBytes)
        {
            return new CsvImportResult(0, [$"CSV size exceeds {options.Value.SingleCsvLimitBytes} bytes."]);
        }

        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        var content = await reader.ReadToEndAsync(cancellationToken);
        var rows = content.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        if (rows.Length <= 1)
        {
            return new CsvImportResult(0, []);
        }

        var headers = SplitCsv(rows[0]);
        var errors = new List<string>();
        var imported = 0;
        var pendingMappings = new List<(int Line, string SourcePath, string RedisKey)>();

        await using var tx = await db.Database.BeginTransactionAsync(cancellationToken);
        var stagedAgents = new Dictionary<string, SnmpAgentConfig>(StringComparer.OrdinalIgnoreCase);
        for (var i = 1; i < rows.Length; i++)
        {
            if (string.IsNullOrWhiteSpace(rows[i]))
            {
                continue;
            }

            var fields = SplitCsv(rows[i]);
            string Get(string name) => Field(headers, fields, name);
            var kind = Get("kind");
            try
            {
                switch (kind)
                {
                    case "agent":
                        var agent = new SnmpAgentConfig
                        {
                            AgentId = Get("agent_id"),
                            DisplayName = Get("display_name"),
                            Host = Get("host"),
                            Port = int.TryParse(Get("port"), out var port) ? port : 161,
                            SnmpVersion = Get("snmp_version"),
                            PreferredMibSetId = await ResolveMibSetIdAsync(Get("preferred_mib_set"), cancellationToken),
                            Description = EmptyToNull(Get("description"))
                        };
                        db.SnmpAgentConfigs.Add(agent);
                        stagedAgents[agent.AgentId] = agent;
                        imported++;
                        break;
                    case "point":
                        var agentId = Get("agent_id");
                        var pointAgent = stagedAgents.TryGetValue(agentId, out var staged)
                            ? staged
                            : await db.SnmpAgentConfigs.FirstAsync(a => a.AgentId == agentId, cancellationToken);
                        var oid = paths.NormalizeNumericOid(Get("numeric_oid"));
                        db.SnmpPointConfigs.Add(new SnmpPointConfig
                        {
                            AgentConfig = pointAgent,
                            PointName = Get("point_name"),
                            NumericOid = oid,
                            SourcePath = paths.BuildPointSourcePath(pointAgent.AgentId, oid),
                            ValueType = EmptyDefault(Get("value_type"), "string"),
                            Access = EmptyDefault(Get("access"), "ro"),
                            MibSetIdUsedForMapping = await ResolveMibSetIdAsync(Get("mib_set_used"), cancellationToken),
                            MibLabel = EmptyToNull(Get("mib_label")),
                            MibModule = EmptyToNull(Get("mib_module")),
                            MibSyntax = EmptyToNull(Get("mib_syntax")),
                            MibAccess = EmptyToNull(Get("mib_access")),
                            MibDescription = EmptyToNull(Get("mib_description")),
                            Description = EmptyToNull(Get("description"))
                        });
                        imported++;
                        break;
                    case "trap_rule":
                        db.SnmpTrapRuleConfigs.Add(new SnmpTrapRuleConfig
                        {
                            AgentId = Get("agent_id"),
                            TrapOid = paths.NormalizeNumericOid(Get("trap_oid")),
                            DisplayName = EmptyDefault(Get("display_name"), Get("trap_oid")),
                            Description = EmptyToNull(Get("description"))
                        });
                        imported++;
                        break;
                    case "mapping":
                        pendingMappings.Add((i + 1, Get("mapping_source_path"), Get("mapping_redis_key")));
                        break;
                }
            }
            catch (Exception ex)
            {
                errors.Add($"Line {i + 1}: {ex.Message}");
            }
        }

        if (errors.Count == 0)
        {
            await db.SaveChangesAsync(cancellationToken);
            foreach (var mapping in pendingMappings)
            {
                var result = await mappingValidation.ValidateAsync(mapping.SourcePath, mapping.RedisKey, null, cancellationToken);
                if (!result.Success)
                {
                    errors.Add($"Line {mapping.Line}: {result.Error}");
                    continue;
                }

                db.RedisMappings.Add(new RedisMapping { SourcePath = mapping.SourcePath, RedisKey = mapping.RedisKey });
                imported++;
            }
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

    private static string Csv(params string[] values) =>
        string.Join(",", values.Select(value => value.Contains(',') || value.Contains('"') || value.Contains('\n')
            ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\""
            : value));

    private static string[] NewExportRow(string kind)
    {
        var row = new string[ExportHeaders.Length];
        Array.Fill(row, "");
        row[0] = kind;
        return row;
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

    private static string Field(IReadOnlyList<string> headers, IReadOnlyList<string> fields, string name)
    {
        var index = Array.FindIndex(headers.ToArray(), header => header.Equals(name, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index < fields.Count ? fields[index] : "";
    }

    private static string EmptyDefault(string value, string fallback) =>
        string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();

    private static string? EmptyToNull(string value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private async Task<int?> ResolveMibSetIdAsync(string nameOrId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(nameOrId))
        {
            return null;
        }
        if (int.TryParse(nameOrId, out var id))
        {
            return id;
        }

        return await db.MibSets
            .AsNoTracking()
            .Where(s => s.Name == nameOrId.Trim())
            .Select(s => (int?)s.Id)
            .FirstOrDefaultAsync(cancellationToken);
    }
}
