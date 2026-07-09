using System.Text.RegularExpressions;
using Ptlk.RedisSnmp.Models;

namespace Ptlk.RedisSnmp.Services.Expressions;

public sealed record ExpressionValidationMessage(string Level, string Field, string Message);

public sealed class ExpressionValidationService
{
    private static readonly Regex Identifier = new("^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.Compiled);

    public IReadOnlyList<ExpressionValidationMessage> Validate(ExpressionConfig expression)
    {
        var messages = new List<ExpressionValidationMessage>();

        if (string.IsNullOrWhiteSpace(expression.Name))
        {
            messages.Add(new("Error", "Name", "Name is required."));
        }

        if (!IsRw(expression.Rw))
        {
            messages.Add(new("Error", "Rw", "Rw must be Ro, Rw, or Wo."));
        }

        if (!ExpressionValueTypes.All.Contains(expression.ValueType, StringComparer.OrdinalIgnoreCase))
        {
            messages.Add(new("Error", "ValueType", "Value type must be double, bool, or string."));
        }

        if (expression.Rw is "Ro" or "Rw")
        {
            if (string.IsNullOrWhiteSpace(expression.ReadReturnParameter))
            {
                messages.Add(new("Error", "ReadReturnParameter", "Read return parameter is required."));
            }
            else if (!Identifier.IsMatch(expression.ReadReturnParameter))
            {
                messages.Add(new("Error", "ReadReturnParameter", "Read return parameter is not a valid identifier."));
            }

            if (string.IsNullOrWhiteSpace(expression.ReadScript))
            {
                messages.Add(new("Error", "ReadScript", "Read script is required."));
            }
        }

        if (expression.Rw is "Wo" or "Rw")
        {
            if (!string.IsNullOrWhiteSpace(expression.WriteInputParameter)
                && !Identifier.IsMatch(expression.WriteInputParameter))
            {
                messages.Add(new("Error", "WriteInputParameter", "Write input parameter is not a valid identifier."));
            }

            if (string.IsNullOrWhiteSpace(expression.WriteScript))
            {
                messages.Add(new("Error", "WriteScript", "Write script is required."));
            }
        }

        foreach (var binding in expression.Bindings)
        {
            if (!Identifier.IsMatch(binding.ParameterName))
            {
                messages.Add(new("Error", binding.ParameterName, "Binding parameter is not a valid identifier."));
            }

            var script = $"{expression.ReadScript}\n{expression.WriteScript}";
            if (!string.IsNullOrWhiteSpace(binding.ParameterName)
                && !script.Contains(binding.ParameterName, StringComparison.Ordinal))
            {
                messages.Add(new("Warning", binding.ParameterName, "Binding parameter is not referenced by the scripts."));
            }
        }

        return messages;
    }

    private static bool IsRw(string value) => value is "Ro" or "Rw" or "Wo";
}
