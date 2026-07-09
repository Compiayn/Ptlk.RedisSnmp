using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Contracts.Trap;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Mib;
using Ptlk.RedisSnmp.Services.Redis;

namespace Ptlk.RedisSnmp.Services.Trap;

public sealed class TrapEventPublisher(
    AppDbContext db,
    MibLookupService mibLookup,
    IRedisPubSubService pubSub,
    TrapSecurityService security,
    IOptions<TrapOptions> trapOptions,
    TrapDiagnosticsRefreshService? diagnosticsRefresh = null)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<SnmpTrapMessage> PublishAsync(
        SnmpTrapMessage message,
        CancellationToken cancellationToken = default)
    {
        var evaluation = await security.EvaluateAsync(message, cancellationToken);
        var publishMode = TrapPublishModes.Normalize(trapOptions.Value.PublishMode);
        var trapOid = string.IsNullOrWhiteSpace(message.TrapOid) || message.TrapOid == "0"
            ? null
            : message.TrapOid;

        var labeled = new List<SnmpTrapVarbind>();
        var labels = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var varbind in message.Varbinds)
        {
            var lookup = await mibLookup.LookupAsync(evaluation.PreferredMibSetId, varbind.Oid, cancellationToken)
                ?? await mibLookup.LookupAsync(varbind.Oid, cancellationToken);
            var label = ToMibLabel(lookup, varbind.Oid);
            labels[varbind.Oid] = label;
            labeled.Add(varbind with { Label = label });
        }

        var trapLookup = trapOid is null
            ? null
            : await mibLookup.LookupAsync(evaluation.PreferredMibSetId, trapOid, cancellationToken)
              ?? await mibLookup.LookupAsync(trapOid, cancellationToken);
        var expectedObjects = trapOid is null
            ? []
            : await LoadExpectedObjectsAsync(evaluation.PreferredMibSetId, trapOid, cancellationToken);
        var expectedMatch = MatchExpectedObjects(expectedObjects, labeled);
        var (publishResult, publishReason) = DecidePublish(
            publishMode,
            evaluation,
            trapOid);

        var enriched = message with
        {
            AgentId = evaluation.ResolvedAgentId ?? "unknown",
            TrapOid = trapOid ?? "",
            Varbinds = labeled
        };
        var diagnostic = new SnmpTrapLogEntry
        {
            AgentId = evaluation.ResolvedAgentId,
            SourceAddress = message.SourceAddress,
            TransportSourcePort = message.SourcePort,
            TrapOid = trapOid ?? "",
            ReceivedAt = enriched.ReceivedAt.UtcDateTime,
            VarbindsJson = JsonSerializer.Serialize(enriched.Varbinds, JsonOptions),
            MibLabelsJson = JsonSerializer.Serialize(labels, JsonOptions),
            RawPayload = enriched.RawPayload,
            ResolvedPayload = JsonSerializer.Serialize(enriched, JsonOptions),
            ExpectedObjects = expectedObjects.Count == 0 ? null : JsonSerializer.Serialize(expectedObjects, JsonOptions),
            ExpectedObjectMatchResult = expectedMatch,
            ResolvedAgentId = evaluation.ResolvedAgentId,
            AgentResolutionResult = evaluation.AgentResolutionResult,
            AgentResolutionReason = evaluation.AgentResolutionReason,
            ResolvedTrapOid = trapOid,
            ResolvedTrapName = trapLookup?.SymbolicName,
            ResolvedTrapModule = trapLookup?.ModuleName,
            ResolvedTrapDescription = trapLookup?.Description,
            PublishMode = publishMode,
            CredentialValidationResult = evaluation.CredentialValidationResult,
            CredentialValidationReason = evaluation.CredentialValidationReason,
            PublishResult = publishResult,
            PublishReason = publishReason
        };
        db.SnmpTrapLogEntries.Add(diagnostic);
        await db.SaveChangesAsync(cancellationToken);
        diagnosticsRefresh?.NotifyDiagnosticRecorded(diagnostic.Id);

        if (publishResult == TrapPublishResults.Published)
        {
            var payload = new
            {
                type = "snmp.trap.received",
                diagnosticId = diagnostic.Id,
                agentId = evaluation.ResolvedAgentId,
                trapOid,
                trapLabel = ToMibLabel(trapLookup, trapOid),
                timestamp = new DateTimeOffset(diagnostic.ReceivedAt).ToUnixTimeMilliseconds(),
                variables = enriched.Varbinds.Select(v => new
                {
                    oid = v.Oid,
                    value = v.Value,
                    syntax = v.Syntax,
                    label = v.Label
                }).ToArray()
            };
            await pubSub.PublishAsync($"evt:snmp-trap:{evaluation.ResolvedAgentId}:{trapOid}", payload, cancellationToken);
        }

        return enriched;
    }

    private static (string PublishResult, string PublishReason) DecidePublish(
        string publishMode,
        TrapSecurityEvaluation evaluation,
        string? trapOid)
    {
        if (evaluation.AgentResolutionResult == TrapAgentResolutionResults.Unresolved)
        {
            return (TrapPublishResults.Skipped, "unresolved-agent");
        }

        if (evaluation.AgentResolutionResult == TrapAgentResolutionResults.Ambiguous)
        {
            return (TrapPublishResults.Skipped, "ambiguous-agent");
        }

        if (evaluation.AgentResolutionResult == TrapAgentResolutionResults.Disabled)
        {
            return (TrapPublishResults.Skipped, "agent-disabled");
        }

        if (string.IsNullOrWhiteSpace(trapOid))
        {
            return (TrapPublishResults.Skipped, "missing-trap-oid");
        }

        if (publishMode == TrapPublishModes.Credential
            && evaluation.CredentialValidationResult != TrapCredentialValidationResults.Accepted)
        {
            return (TrapPublishResults.Skipped, "credential-rejected");
        }

        return (TrapPublishResults.Published, "published");
    }

    private async Task<List<ExpectedTrapObjectSnapshot>> LoadExpectedObjectsAsync(
        int? mibSetId,
        string trapOid,
        CancellationToken cancellationToken)
    {
        var query = db.MibNodes
            .AsNoTracking()
            .Include(n => n.NotificationObjects)
            .Where(n => n.NumericOid == trapOid && n.NodeKind == "NOTIFICATION-TYPE");
        if (mibSetId is not null)
        {
            query = query.Where(n => n.MibSetId == mibSetId);
        }

        var node = await query.OrderBy(n => n.Id).FirstOrDefaultAsync(cancellationToken);
        if (node is null && mibSetId is not null)
        {
            node = await db.MibNodes
                .AsNoTracking()
                .Include(n => n.NotificationObjects)
                .Where(n => n.Active && n.NumericOid == trapOid && n.NodeKind == "NOTIFICATION-TYPE")
                .OrderBy(n => n.Id)
                .FirstOrDefaultAsync(cancellationToken);
        }

        return node?.NotificationObjects
                   .OrderBy(o => o.SortOrder)
                   .Select(o => new ExpectedTrapObjectSnapshot(o.SortOrder, o.ObjectSymbol, o.ObjectOid))
                   .ToList()
               ?? [];
    }

    private static string? MatchExpectedObjects(
        IReadOnlyList<ExpectedTrapObjectSnapshot> expectedObjects,
        IReadOnlyList<SnmpTrapVarbind> varbinds)
    {
        if (expectedObjects.Count == 0)
        {
            return null;
        }

        var matched = 0;
        var missing = new List<string>();
        foreach (var expected in expectedObjects)
        {
            if (!string.IsNullOrWhiteSpace(expected.ObjectOid)
                && varbinds.Any(v => v.Oid == expected.ObjectOid || v.Oid.StartsWith(expected.ObjectOid + ".", StringComparison.Ordinal)))
            {
                matched++;
            }
            else
            {
                missing.Add(expected.ObjectSymbol);
            }
        }

        return JsonSerializer.Serialize(new
        {
            expected = expectedObjects.Count,
            matched,
            missing
        }, JsonOptions);
    }

    private static string? ToMibLabel(Ptlk.RedisSnmp.Contracts.Mib.MibLookupResult? lookup, string? oid)
    {
        if (string.IsNullOrWhiteSpace(lookup?.SymbolicName))
        {
            return null;
        }

        var symbolicName = lookup.SymbolicName;
        if (!string.IsNullOrWhiteSpace(oid)
            && !string.IsNullOrWhiteSpace(lookup.NumericOid)
            && oid.StartsWith(lookup.NumericOid + ".", StringComparison.Ordinal))
        {
            symbolicName += oid[lookup.NumericOid.Length..];
        }

        return string.IsNullOrWhiteSpace(lookup.ModuleName)
            ? symbolicName
            : $"{lookup.ModuleName}::{symbolicName}";
    }

    private sealed record ExpectedTrapObjectSnapshot(int SortOrder, string ObjectSymbol, string? ObjectOid);
}
