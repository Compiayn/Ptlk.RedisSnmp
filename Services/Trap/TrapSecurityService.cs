using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Contracts.Trap;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;

namespace Ptlk.RedisSnmp.Services.Trap;

public sealed record TrapSecurityEvaluation(
    SnmpAgentConfig? Agent,
    string? ResolvedAgentId,
    int? PreferredMibSetId,
    string AgentResolutionResult,
    string AgentResolutionReason,
    string CredentialValidationResult,
    string CredentialValidationReason);

public sealed class TrapSecurityService(
    AppDbContext db,
    SnmpTrapCredentialService trapCredentials)
{
    public async Task<TrapSecurityEvaluation> EvaluateAsync(
        SnmpTrapMessage message,
        CancellationToken cancellationToken = default)
    {
        var sourceAddress = message.SourceAddress.Trim();
        var agents = await db.SnmpAgentConfigs
            .AsNoTracking()
            .Include(a => a.TrapCredentialConfig)
            .Where(a => a.Host == sourceAddress)
            .ToListAsync(cancellationToken);

        if (agents.Count == 0)
        {
            return NotApplicable(
                TrapAgentResolutionResults.Unresolved,
                "unmatched-source",
                "unresolved-agent");
        }

        if (agents.Count > 1)
        {
            return NotApplicable(
                TrapAgentResolutionResults.Ambiguous,
                "ambiguous-agent",
                "ambiguous-agent");
        }

        var agent = agents[0];
        if (!agent.Enabled)
        {
            return new TrapSecurityEvaluation(
                agent,
                agent.AgentId,
                agent.PreferredMibSetId,
                TrapAgentResolutionResults.Disabled,
                "agent-disabled",
                TrapCredentialValidationResults.NotApplicable,
                "agent-disabled");
        }

        if (agent.TrapCredentialConfigId is null)
        {
            return new TrapSecurityEvaluation(
                agent,
                agent.AgentId,
                agent.PreferredMibSetId,
                TrapAgentResolutionResults.Resolved,
                "matched-agent-host",
                TrapCredentialValidationResults.NotConfigured,
                "agent-trap-credential-not-configured");
        }

        var credential = agent.TrapCredentialConfig;
        if (credential is null)
        {
            return new TrapSecurityEvaluation(
                agent,
                agent.AgentId,
                agent.PreferredMibSetId,
                TrapAgentResolutionResults.Resolved,
                "matched-agent-host",
                TrapCredentialValidationResults.NotConfigured,
                "agent-trap-credential-not-configured");
        }

        if (!credential.Enabled)
        {
            return new TrapSecurityEvaluation(
                agent,
                agent.AgentId,
                agent.PreferredMibSetId,
                TrapAgentResolutionResults.Resolved,
                "matched-agent-host",
                TrapCredentialValidationResults.Disabled,
                "agent-trap-credential-disabled");
        }

        var accepted = ValidateCredential(message, credential);
        return new TrapSecurityEvaluation(
            agent,
            agent.AgentId,
            agent.PreferredMibSetId,
            TrapAgentResolutionResults.Resolved,
            "matched-agent-host",
            accepted ? TrapCredentialValidationResults.Accepted : TrapCredentialValidationResults.Rejected,
            accepted ? "credential-accepted" : "credential-rejected");
    }

    private bool ValidateCredential(SnmpTrapMessage message, SnmpTrapCredentialConfig credential)
    {
        var messageVersion = NormalizeVersion(message.Version);
        if (messageVersion is not null
            && !string.Equals(messageVersion, credential.Version, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (credential.Version is SnmpVersions.V1 or SnmpVersions.V2C)
        {
            var secrets = trapCredentials.RevealSecrets(credential);
            return !string.IsNullOrWhiteSpace(secrets.Community)
                   && string.Equals(secrets.Community, message.Community, StringComparison.Ordinal);
        }

        if (!string.IsNullOrWhiteSpace(credential.SecurityName)
            && !string.Equals(credential.SecurityName, message.SecurityName, StringComparison.Ordinal))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(credential.SecurityLevel)
            && !string.Equals(credential.SecurityLevel, message.SecurityLevel, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(credential.EngineId)
            && !string.Equals(credential.EngineId, message.EngineId, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !string.IsNullOrWhiteSpace(credential.SecurityName)
               || !string.IsNullOrWhiteSpace(credential.EngineId);
    }

    private static TrapSecurityEvaluation NotApplicable(
        string agentResolutionResult,
        string agentResolutionReason,
        string credentialValidationReason) =>
        new(
            null,
            null,
            null,
            agentResolutionResult,
            agentResolutionReason,
            TrapCredentialValidationResults.NotApplicable,
            credentialValidationReason);

    private static string? NormalizeVersion(string? version)
    {
        var value = version?.Trim();
        return value?.ToLowerInvariant() switch
        {
            "1" or "v1" => SnmpVersions.V1,
            "2" or "2c" or "v2c" => SnmpVersions.V2C,
            "3" or "v3" => SnmpVersions.V3,
            _ => string.IsNullOrWhiteSpace(value) ? null : value
        };
    }
}
