using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Contracts.Mib;
using Ptlk.RedisSnmp.Data;

namespace Ptlk.RedisSnmp.Services.Mib;

public sealed class MibLookupService(AppDbContext db)
{
    public async Task<MibLookupResult?> LookupAsync(string oidOrSymbol, CancellationToken cancellationToken = default)
    {
        var value = oidOrSymbol.Trim().TrimStart('.');
        var query = db.MibNodes.AsNoTracking().Where(node => node.Active);
        var node = await FindNodeAsync(query, value, oidOrSymbol, cancellationToken);

        return node is null ? null : ToResult(node);
    }

    public async Task<MibLookupResult?> LookupAsync(int? mibSetId, string oidOrSymbol, CancellationToken cancellationToken = default)
    {
        var value = oidOrSymbol.Trim().TrimStart('.');
        if (mibSetId is null)
        {
            return null;
        }

        var query = db.MibNodes.AsNoTracking().Where(node => node.MibSetId == mibSetId);
        var node = await FindNodeAsync(query, value, oidOrSymbol, cancellationToken);

        return node is null ? null : ToResult(node);
    }

    public Task<List<MibLookupResult>> ListActiveAsync(CancellationToken cancellationToken = default) =>
        db.MibNodes.AsNoTracking()
            .Where(node => node.Active)
            .OrderBy(node => node.NumericOid)
            .Select(node => new MibLookupResult(node.NumericOid, node.SymbolicName, node.ModuleName, node.Syntax, node.Access, node.Description, node.MibSetId))
            .ToListAsync(cancellationToken);

    public Task<List<MibLookupResult>> ListBySetAsync(int mibSetId, CancellationToken cancellationToken = default) =>
        db.MibNodes.AsNoTracking()
            .Where(node => node.MibSetId == mibSetId)
            .OrderBy(node => node.NumericOid)
            .ThenBy(node => node.SymbolicName)
            .Select(node => new MibLookupResult(node.NumericOid, node.SymbolicName, node.ModuleName, node.Syntax, node.Access, node.Description, node.MibSetId))
            .ToListAsync(cancellationToken);

    private static async Task<Ptlk.RedisSnmp.Models.MibNode?> FindNodeAsync(
        IQueryable<Ptlk.RedisSnmp.Models.MibNode> query,
        string normalizedOid,
        string oidOrSymbol,
        CancellationToken cancellationToken)
    {
        var exact = await query.OrderBy(n => n.Id).FirstOrDefaultAsync(n => n.NumericOid == normalizedOid, cancellationToken)
            ?? await query.OrderBy(n => n.Id).FirstOrDefaultAsync(n => n.SymbolicName == oidOrSymbol, cancellationToken);
        if (exact is not null)
        {
            return exact;
        }

        if (!normalizedOid.All(ch => char.IsDigit(ch) || ch == '.'))
        {
            return null;
        }

        var nodes = await query.ToListAsync(cancellationToken);
        return nodes
            .Where(n => normalizedOid.StartsWith(n.NumericOid + ".", StringComparison.Ordinal))
            .OrderByDescending(n => n.NumericOid.Length)
            .ThenBy(n => n.Id)
            .FirstOrDefault();
    }

    private static MibLookupResult ToResult(Ptlk.RedisSnmp.Models.MibNode node) =>
        new(node.NumericOid, node.SymbolicName, node.ModuleName, node.Syntax, node.Access, node.Description, node.MibSetId);
}
