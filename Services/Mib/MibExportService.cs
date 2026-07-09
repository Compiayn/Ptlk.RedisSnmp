using System.Text;
using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Contracts.Mib;
using Ptlk.RedisSnmp.Data;

namespace Ptlk.RedisSnmp.Services.Mib;

public sealed class MibExportService(AppDbContext db)
{
    public async Task<ProjectMibExport> ExportProjectMibAsync(int? mibSetId = null, CancellationToken cancellationToken = default)
    {
        var query = db.MibNodes.AsNoTracking();
        query = mibSetId.HasValue
            ? query.Where(node => node.MibSetId == mibSetId.Value)
            : query.Where(node => node.Active);
        var nodes = await query.OrderBy(node => node.NumericOid).ToListAsync(cancellationToken);

        var builder = new StringBuilder();
        builder.AppendLine("PTLK-REDIS-SNMP-MIB DEFINITIONS ::= BEGIN");
        builder.AppendLine("-- Generated project MIB metadata snapshot.");
        foreach (var node in nodes)
        {
            builder.AppendLine($"-- {node.NumericOid} {node.SymbolicName ?? "-"} {node.NodeKind ?? "-"} {node.Syntax ?? "-"} {node.Access ?? "-"}");
        }
        builder.AppendLine("END");

        return new ProjectMibExport("ptlk-redis-snmp-project.mib", "text/plain", builder.ToString());
    }
}
