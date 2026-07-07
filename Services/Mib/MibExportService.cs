using System.Text;
using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Contracts.Mib;
using Ptlk.RedisSnmp.Data;

namespace Ptlk.RedisSnmp.Services.Mib;

public sealed class MibExportService(AppDbContext db)
{
    public async Task<ProjectMibExport> ExportProjectMibAsync(CancellationToken cancellationToken = default)
    {
        var nodes = await db.MibNodes.AsNoTracking()
            .Where(node => node.Active)
            .OrderBy(node => node.NumericOid)
            .ToListAsync(cancellationToken);

        var builder = new StringBuilder();
        builder.AppendLine("PTLK-REDIS-SNMP-MIB DEFINITIONS ::= BEGIN");
        builder.AppendLine("-- Generated project MIB metadata snapshot.");
        foreach (var node in nodes)
        {
            builder.AppendLine($"-- {node.NumericOid} {node.SymbolicName ?? "-"} {node.Syntax ?? "-"} {node.Access ?? "-"}");
        }
        builder.AppendLine("END");

        return new ProjectMibExport("ptlk-redis-snmp-project.mib", "text/plain", builder.ToString());
    }
}
