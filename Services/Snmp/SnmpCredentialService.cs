using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;

namespace Ptlk.RedisSnmp.Services.Snmp;

public sealed record SnmpCredentialSecrets(
    string? ReadCommunity,
    string? WriteCommunity,
    string? AuthPassword,
    string? PrivPassword);

public sealed class SnmpCredentialService(
    AppDbContext db,
    IDataProtectionProvider dataProtectionProvider)
{
    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector("Ptlk.RedisSnmp.SnmpCredential");

    public Task<List<SnmpCredentialConfig>> ListAsync(CancellationToken cancellationToken = default) =>
        db.SnmpCredentialConfigs
            .AsNoTracking()
            .OrderBy(c => c.Name)
            .ToListAsync(cancellationToken);

    public async Task<SnmpCredentialConfig> CreateOrUpdateAsync(
        SnmpCredentialConfig input,
        SnmpCredentialSecrets secrets,
        CancellationToken cancellationToken = default)
    {
        Validate(input);
        var entity = input.Id > 0
            ? await db.SnmpCredentialConfigs.FirstAsync(c => c.Id == input.Id, cancellationToken)
            : new SnmpCredentialConfig();

        entity.Name = input.Name.Trim();
        entity.Version = input.Version.Trim();
        entity.SecurityName = NullIfWhiteSpace(input.SecurityName);
        entity.SecurityLevel = NullIfWhiteSpace(input.SecurityLevel);
        entity.AuthProtocol = NullIfWhiteSpace(input.AuthProtocol);
        entity.PrivProtocol = NullIfWhiteSpace(input.PrivProtocol);
        entity.Description = NullIfWhiteSpace(input.Description);

        if (!string.IsNullOrWhiteSpace(secrets.ReadCommunity))
        {
            entity.ProtectedReadCommunity = _protector.Protect(secrets.ReadCommunity);
        }
        if (!string.IsNullOrWhiteSpace(secrets.WriteCommunity))
        {
            entity.ProtectedWriteCommunity = _protector.Protect(secrets.WriteCommunity);
        }
        if (!string.IsNullOrWhiteSpace(secrets.AuthPassword))
        {
            entity.ProtectedAuthPassword = _protector.Protect(secrets.AuthPassword);
        }
        if (!string.IsNullOrWhiteSpace(secrets.PrivPassword))
        {
            entity.ProtectedPrivPassword = _protector.Protect(secrets.PrivPassword);
        }

        if (input.Id <= 0)
        {
            db.SnmpCredentialConfigs.Add(entity);
        }

        await db.SaveChangesAsync(cancellationToken);
        return entity;
    }

    public async Task DeleteAsync(int id, CancellationToken cancellationToken = default)
    {
        var entity = await db.SnmpCredentialConfigs.FindAsync([id], cancellationToken);
        if (entity is null)
        {
            return;
        }

        db.SnmpCredentialConfigs.Remove(entity);
        await db.SaveChangesAsync(cancellationToken);
    }

    public SnmpCredentialSecrets RevealSecrets(SnmpCredentialConfig credential) =>
        new(
            UnprotectOrNull(credential.ProtectedReadCommunity) ?? UnprotectOrNull(credential.ProtectedCommunity),
            UnprotectOrNull(credential.ProtectedWriteCommunity) ?? UnprotectOrNull(credential.ProtectedCommunity),
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

    private static void Validate(SnmpCredentialConfig credential)
    {
        if (string.IsNullOrWhiteSpace(credential.Name))
        {
            throw new InvalidOperationException("Credential name is required.");
        }

        if (credential.Version is not SnmpVersions.V1 and not SnmpVersions.V2C and not SnmpVersions.V3)
        {
            throw new InvalidOperationException("Credential version must be v1, v2c, or v3.");
        }
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
