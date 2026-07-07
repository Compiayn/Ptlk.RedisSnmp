using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;

namespace Ptlk.RedisSnmp.Services.Logs;

public sealed record LogQuery(
    string? Keyword,
    string? Category,
    string? Level,
    string? AgentId,
    string? NumericOid,
    string? CommandId,
    int Page,
    int PageSize);

public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

public sealed class LogService(AppDbContext db)
{
    public async Task AddSystemAsync(
        string category,
        string level,
        string message,
        string? commandId = null,
        CancellationToken cancellationToken = default)
    {
        db.SystemLogEntries.Add(new SystemLogEntry
        {
            Category = category,
            Level = level,
            Message = message,
            CommandId = commandId
        });
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task AddSnmpAsync(
        string? agentId,
        string? numericOid,
        string operation,
        string level,
        string message,
        string? commandId = null,
        string? errorCode = null,
        int? durationMs = null,
        CancellationToken cancellationToken = default)
    {
        db.SnmpLogEntries.Add(new SnmpLogEntry
        {
            AgentId = agentId,
            NumericOid = numericOid,
            Operation = operation,
            Level = level,
            Message = message,
            CommandId = commandId,
            ErrorCode = errorCode,
            DurationMs = durationMs
        });
        await db.SaveChangesAsync(cancellationToken);
    }

    public async Task<PagedResult<SystemLogEntry>> QuerySystemAsync(
        LogQuery query,
        CancellationToken cancellationToken = default)
    {
        var page = Math.Max(query.Page, 1);
        var pageSize = Math.Clamp(query.PageSize, 10, 200);
        var q = db.SystemLogEntries.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(query.Keyword))
        {
            q = q.Where(l => l.Message.Contains(query.Keyword));
        }
        if (!string.IsNullOrWhiteSpace(query.Category))
        {
            q = q.Where(l => l.Category == query.Category);
        }
        if (!string.IsNullOrWhiteSpace(query.Level))
        {
            q = q.Where(l => l.Level == query.Level);
        }
        if (!string.IsNullOrWhiteSpace(query.CommandId))
        {
            q = q.Where(l => l.CommandId == query.CommandId);
        }

        var total = await q.CountAsync(cancellationToken);
        var items = await q.OrderByDescending(l => l.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(cancellationToken);

        return new PagedResult<SystemLogEntry>(items, total, page, pageSize);
    }

    public async Task<IReadOnlyList<SnmpLogEntry>> QueryRecentSnmpAsync(
        LogQuery query,
        CancellationToken cancellationToken = default)
    {
        var pageSize = Math.Clamp(query.PageSize, 10, 500);
        var q = db.SnmpLogEntries.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(query.Keyword))
        {
            q = q.Where(l => l.Message.Contains(query.Keyword));
        }
        if (!string.IsNullOrWhiteSpace(query.AgentId))
        {
            q = q.Where(l => l.AgentId == query.AgentId);
        }
        if (!string.IsNullOrWhiteSpace(query.NumericOid))
        {
            q = q.Where(l => l.NumericOid == query.NumericOid);
        }
        if (!string.IsNullOrWhiteSpace(query.CommandId))
        {
            q = q.Where(l => l.CommandId == query.CommandId);
        }

        return await q.OrderByDescending(l => l.CreatedAt)
            .Take(pageSize)
            .ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<SnmpTrapLogEntry>> QueryRecentTrapsAsync(
        string? agentId = null,
        string? trapOid = null,
        int take = 100,
        CancellationToken cancellationToken = default)
    {
        var q = db.SnmpTrapLogEntries.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(agentId))
        {
            q = q.Where(l => l.AgentId == agentId);
        }
        if (!string.IsNullOrWhiteSpace(trapOid))
        {
            q = q.Where(l => l.TrapOid == trapOid);
        }

        return await q.OrderByDescending(l => l.ReceivedAt)
            .Take(Math.Clamp(take, 10, 500))
            .ToListAsync(cancellationToken);
    }
}
