using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;

namespace Ptlk.RedisSnmp.Services.Expressions;

public sealed class ExpressionService(
    AppDbContext db,
    ExpressionValidationService validator)
{
    public Task<List<ExpressionConfig>> ListAsync(CancellationToken cancellationToken = default) =>
        db.ExpressionConfigs
            .AsNoTracking()
            .Include(e => e.Bindings)
            .OrderBy(e => e.Name)
            .ToListAsync(cancellationToken);

    public async Task<ExpressionConfig> AddAsync(ExpressionConfig expression, CancellationToken cancellationToken = default)
    {
        Normalize(expression);
        var validation = validator.Validate(expression);
        if (validation.Any(m => m.Level == "Error"))
        {
            throw new InvalidOperationException(string.Join(" ", validation.Where(m => m.Level == "Error").Select(m => m.Message)));
        }

        db.ExpressionConfigs.Add(expression);
        await db.SaveChangesAsync(cancellationToken);
        return expression;
    }

    public async Task<ExpressionConfig> UpdateAsync(int id, ExpressionConfig input, CancellationToken cancellationToken = default)
    {
        var expression = await db.ExpressionConfigs
            .Include(e => e.Bindings)
            .FirstAsync(e => e.Id == id, cancellationToken);
        var oldSourcePath = SourcePath(expression);

        expression.Name = input.Name;
        expression.Description = input.Description;
        expression.Rw = input.Rw;
        expression.ValueType = input.ValueType;
        expression.ReadReturnParameter = input.ReadReturnParameter;
        expression.ReadScript = input.ReadScript;
        expression.WriteInputParameter = input.WriteInputParameter;
        expression.WriteScript = input.WriteScript;
        expression.Bindings.Clear();
        foreach (var binding in input.Bindings)
        {
            expression.Bindings.Add(new ExpressionBinding
            {
                ParameterName = binding.ParameterName,
                SourcePath = binding.SourcePath
            });
        }

        Normalize(expression);
        var validation = validator.Validate(expression);
        if (validation.Any(m => m.Level == "Error"))
        {
            throw new InvalidOperationException(string.Join(" ", validation.Where(m => m.Level == "Error").Select(m => m.Message)));
        }

        var newSourcePath = SourcePath(expression);
        if (!string.Equals(oldSourcePath, newSourcePath, StringComparison.Ordinal))
        {
            var mappings = await db.RedisMappings
                .Where(m => m.SourcePath == oldSourcePath)
                .ToListAsync(cancellationToken);
            foreach (var mapping in mappings)
            {
                mapping.SourcePath = newSourcePath;
            }
        }

        await db.SaveChangesAsync(cancellationToken);
        return expression;
    }

    public async Task DeleteAsync(int id, CancellationToken cancellationToken = default)
    {
        var expression = await db.ExpressionConfigs.FindAsync([id], cancellationToken);
        if (expression is null)
        {
            return;
        }

        var sourcePath = SourcePath(expression);
        var mappings = await db.RedisMappings
            .Where(m => m.SourcePath == sourcePath)
            .ToListAsync(cancellationToken);

        db.RedisMappings.RemoveRange(mappings);
        db.ExpressionConfigs.Remove(expression);
        await db.SaveChangesAsync(cancellationToken);
    }

    public string SourcePath(ExpressionConfig expression) => SourcePathFor(expression.Name);

    public static string SourcePathFor(string name) => $"exp:{name}";

    private static void Normalize(ExpressionConfig expression)
    {
        expression.Name = expression.Name.Trim();
        expression.Description = string.IsNullOrWhiteSpace(expression.Description) ? null : expression.Description.Trim();
        expression.Rw = expression.Rw.Equals("Rw", StringComparison.OrdinalIgnoreCase) ? "Rw"
            : expression.Rw.Equals("Wo", StringComparison.OrdinalIgnoreCase) ? "Wo"
            : "Ro";
        expression.ValueType = ExpressionValueTypes.Normalize(expression.ValueType);
        foreach (var binding in expression.Bindings)
        {
            binding.ParameterName = binding.ParameterName.Trim();
            binding.SourcePath = binding.SourcePath.Trim();
        }
    }
}
