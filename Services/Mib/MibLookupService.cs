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
        var node = await query.FirstOrDefaultAsync(n => n.NumericOid == value, cancellationToken)
            ?? await query.FirstOrDefaultAsync(n => n.SymbolicName == oidOrSymbol, cancellationToken);

        return node is null
            ? null
            : new MibLookupResult(node.NumericOid, node.SymbolicName, node.ModuleName, node.Syntax, node.Access, node.Description);
    }

    public Task<List<MibLookupResult>> ListActiveAsync(CancellationToken cancellationToken = default) =>
        db.MibNodes.AsNoTracking()
            .Where(node => node.Active)
            .OrderBy(node => node.NumericOid)
            .Select(node => new MibLookupResult(node.NumericOid, node.SymbolicName, node.ModuleName, node.Syntax, node.Access, node.Description))
            .ToListAsync(cancellationToken);
}
