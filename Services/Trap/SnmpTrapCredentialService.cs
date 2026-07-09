using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;

namespace Ptlk.RedisSnmp.Services.Trap;

public sealed record SnmpTrapCredentialSecrets(
    string? Community,
    string? AuthPassword,
    string? PrivPassword,
    bool ClearCommunity = false,
    bool ClearAuthPassword = false,
    bool ClearPrivPassword = false);

public sealed class SnmpTrapCredentialService(
    AppDbContext db,
    IDataProtectionProvider dataProtectionProvider)
{
    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector("Ptlk.RedisSnmp.SnmpTrapCredential");

    public Task<List<SnmpTrapCredentialConfig>> ListAsync(CancellationToken cancellationToken = default) =>
        db.SnmpTrapCredentialConfigs
            .AsNoTracking()
            .OrderBy(c => c.Name)
            .ToListAsync(cancellationToken);

    public async Task<SnmpTrapCredentialConfig> CreateOrUpdateAsync(
        SnmpTrapCredentialConfig input,
        SnmpTrapCredentialSecrets secrets,
        CancellationToken cancellationToken = default)
    {
        Validate(input);

        var entity = input.Id > 0
            ? await db.SnmpTrapCredentialConfigs.FirstAsync(c => c.Id == input.Id, cancellationToken)
            : new SnmpTrapCredentialConfig();

        entity.Name = input.Name.Trim();
        entity.Enabled = input.Enabled;
        entity.Version = input.Version.Trim();
        entity.SecurityName = NullIfWhiteSpace(input.SecurityName);
        entity.SecurityLevel = NullIfWhiteSpace(input.SecurityLevel);
        entity.AuthProtocol = NullIfWhiteSpace(input.AuthProtocol);
        entity.PrivProtocol = NullIfWhiteSpace(input.PrivProtocol);
        entity.EngineId = NullIfWhiteSpace(input.EngineId);
        entity.Description = NullIfWhiteSpace(input.Description);

        if (secrets.ClearCommunity)
        {
            entity.ProtectedCommunity = null;
        }
        else if (!string.IsNullOrWhiteSpace(secrets.Community))
        {
            entity.ProtectedCommunity = _protector.Protect(secrets.Community);
        }

        if (secrets.ClearAuthPassword)
        {
            entity.ProtectedAuthPassword = null;
        }
        else if (!string.IsNullOrWhiteSpace(secrets.AuthPassword))
        {
            entity.ProtectedAuthPassword = _protector.Protect(secrets.AuthPassword);
        }

        if (secrets.ClearPrivPassword)
        {
            entity.ProtectedPrivPassword = null;
        }
        else if (!string.IsNullOrWhiteSpace(secrets.PrivPassword))
        {
            entity.ProtectedPrivPassword = _protector.Protect(secrets.PrivPassword);
        }

        if (input.Id <= 0)
        {
            db.SnmpTrapCredentialConfigs.Add(entity);
        }

        await db.SaveChangesAsync(cancellationToken);
        return entity;
    }

    public async Task DeleteAsync(int id, CancellationToken cancellationToken = default)
    {
        var entity = await db.SnmpTrapCredentialConfigs.FindAsync([id], cancellationToken);
        if (entity is null)
        {
            return;
        }

        db.SnmpTrapCredentialConfigs.Remove(entity);
        await db.SaveChangesAsync(cancellationToken);
    }

    public SnmpTrapCredentialSecrets RevealSecrets(SnmpTrapCredentialConfig credential) =>
        new(
            UnprotectOrNull(credential.ProtectedCommunity),
            UnprotectOrNull(credential.ProtectedAuthPassword),
            UnprotectOrNull(credential.ProtectedPrivPassword));

    private string? UnprotectOrNull(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return _protector.Unprotect(value);
    }

    private static void Validate(SnmpTrapCredentialConfig credential)
    {
        if (string.IsNullOrWhiteSpace(credential.Name))
        {
            throw new InvalidOperationException("Trap credential name is required.");
        }

        if (credential.Version is not SnmpVersions.V1 and not SnmpVersions.V2C and not SnmpVersions.V3)
        {
            throw new InvalidOperationException("Trap credential version must be v1, v2c, or v3.");
        }
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
