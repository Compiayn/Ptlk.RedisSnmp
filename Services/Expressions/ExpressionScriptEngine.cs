using System.Globalization;

namespace Ptlk.RedisSnmp.Services.Expressions;

public sealed record ExpressionScriptResult(
    IReadOnlyDictionary<string, object?> Variables,
    IReadOnlySet<string> AssignedVariables);

public sealed class ExpressionScriptEngine
{
    public ExpressionScriptResult Execute(
        string script,
        IReadOnlyDictionary<string, object?> variables,
        CancellationToken cancellationToken = default)
    {
        var state = new Dictionary<string, object?>(variables, StringComparer.Ordinal);
        var assigned = new HashSet<string>(StringComparer.Ordinal);

        foreach (var statement in SplitStatements(script))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var trimmed = statement.Trim();
            if (trimmed.Length == 0)
            {
                continue;
            }

            if (trimmed.StartsWith("return ", StringComparison.Ordinal))
            {
                _ = Evaluate(trimmed[7..], state);
                continue;
            }

            var assignmentIndex = FindAssignment(trimmed);
            if (assignmentIndex > 0)
            {
                var name = trimmed[..assignmentIndex].Trim();
                if (!IsIdentifier(name))
                {
                    throw new InvalidOperationException($"Invalid assignment target '{name}'.");
                }

                var value = Evaluate(trimmed[(assignmentIndex + 1)..], state);
                state[name] = value;
                assigned.Add(name);
                continue;
            }

            _ = Evaluate(trimmed, state);
        }

        return new ExpressionScriptResult(state, assigned);
    }

    private static object? Evaluate(string expression, IReadOnlyDictionary<string, object?> variables)
    {
        var parser = new Parser(expression, variables);
        var value = parser.ParseExpression();
        parser.ExpectEnd();
        return value;
    }

    private static IReadOnlyList<string> SplitStatements(string script)
    {
        var result = new List<string>();
        var start = 0;
        var quote = '\0';
        for (var index = 0; index < script.Length; index++)
        {
            var ch = script[index];
            if (quote != '\0')
            {
                if (ch == quote)
                {
                    quote = '\0';
                }

                continue;
            }

            if (ch is '"' or '\'')
            {
                quote = ch;
            }
            else if (ch is ';' or '\r' or '\n')
            {
                result.Add(script[start..index]);
                start = index + 1;
            }
        }

        if (start < script.Length)
        {
            result.Add(script[start..]);
        }

        return result;
    }

    private static int FindAssignment(string statement)
    {
        var quote = '\0';
        for (var index = 0; index < statement.Length; index++)
        {
            var ch = statement[index];
            if (quote != '\0')
            {
                if (ch == quote)
                {
                    quote = '\0';
                }

                continue;
            }

            if (ch is '"' or '\'')
            {
                quote = ch;
            }
            else if (ch == '=')
            {
                var before = index > 0 ? statement[index - 1] : '\0';
                var after = index + 1 < statement.Length ? statement[index + 1] : '\0';
                if (before is '<' or '>' or '!' or '=' || after == '=')
                {
                    continue;
                }

                return index;
            }
        }

        return -1;
    }

    private static bool IsIdentifier(string value) =>
        value.Length > 0
        && (value[0] == '_' || value[0] is >= 'A' and <= 'Z' || value[0] is >= 'a' and <= 'z')
        && value.All(ch => ch == '_' || ch is >= 'A' and <= 'Z' || ch is >= 'a' and <= 'z' || ch is >= '0' and <= '9');

    private sealed class Parser(string text, IReadOnlyDictionary<string, object?> variables)
    {
        private int index;

        public object? ParseExpression() => ParseOr();

        public void ExpectEnd()
        {
            SkipWhitespace();
            if (index < text.Length)
            {
                throw new InvalidOperationException($"Unexpected token near '{text[index..]}'.");
            }
        }

        private object? ParseOr()
        {
            var left = ParseAnd();
            while (Match("||"))
            {
                var right = ParseAnd();
                left = ToBoolean(left) || ToBoolean(right);
            }

            return left;
        }

        private object? ParseAnd()
        {
            var left = ParseEquality();
            while (Match("&&"))
            {
                var right = ParseEquality();
                left = ToBoolean(left) && ToBoolean(right);
            }

            return left;
        }

        private object? ParseEquality()
        {
            var left = ParseComparison();
            while (true)
            {
                if (Match("=="))
                {
                    left = Compare(left, ParseComparison()) == 0;
                }
                else if (Match("!="))
                {
                    left = Compare(left, ParseComparison()) != 0;
                }
                else
                {
                    return left;
                }
            }
        }

        private object? ParseComparison()
        {
            var left = ParseTerm();
            while (true)
            {
                if (Match(">="))
                {
                    left = Compare(left, ParseTerm()) >= 0;
                }
                else if (Match("<="))
                {
                    left = Compare(left, ParseTerm()) <= 0;
                }
                else if (Match(">"))
                {
                    left = Compare(left, ParseTerm()) > 0;
                }
                else if (Match("<"))
                {
                    left = Compare(left, ParseTerm()) < 0;
                }
                else
                {
                    return left;
                }
            }
        }

        private object? ParseTerm()
        {
            var left = ParseFactor();
            while (true)
            {
                if (Match("+"))
                {
                    var right = ParseFactor();
                    left = left is string || right is string
                        ? Convert.ToString(left, CultureInfo.InvariantCulture) + Convert.ToString(right, CultureInfo.InvariantCulture)
                        : RequireFinite(ToDouble(left) + ToDouble(right));
                }
                else if (Match("-"))
                {
                    left = RequireFinite(ToDouble(left) - ToDouble(ParseFactor()));
                }
                else
                {
                    return left;
                }
            }
        }

        private object? ParseFactor()
        {
            var left = ParseUnary();
            while (true)
            {
                if (Match("*"))
                {
                    left = RequireFinite(ToDouble(left) * ToDouble(ParseUnary()));
                }
                else if (Match("/"))
                {
                    var denominator = ToDouble(ParseUnary());
                    if (denominator == 0d)
                    {
                        throw new InvalidOperationException("Division by zero.");
                    }

                    left = RequireFinite(ToDouble(left) / denominator);
                }
                else if (Match("%"))
                {
                    var denominator = ToDouble(ParseUnary());
                    if (denominator == 0d)
                    {
                        throw new InvalidOperationException("Division by zero.");
                    }

                    left = RequireFinite(ToDouble(left) % denominator);
                }
                else
                {
                    return left;
                }
            }
        }

        private object? ParseUnary()
        {
            if (Match("!"))
            {
                return !ToBoolean(ParseUnary());
            }

            if (Match("-"))
            {
                return RequireFinite(-ToDouble(ParseUnary()));
            }

            return ParsePrimary();
        }

        private object? ParsePrimary()
        {
            SkipWhitespace();
            if (Match("("))
            {
                var value = ParseExpression();
                if (!Match(")"))
                {
                    throw new InvalidOperationException("Missing closing parenthesis.");
                }

                return value;
            }

            if (Peek() is '"' or '\'')
            {
                return ParseString();
            }

            if (char.IsDigit(Peek()) || Peek() == '.')
            {
                return ParseNumber();
            }

            if (IsIdentifierStart(Peek()))
            {
                var identifier = ParseIdentifier();
                if (identifier.Equals("true", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                if (identifier.Equals("false", StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                return variables.TryGetValue(identifier, out var value)
                    ? value
                    : throw new InvalidOperationException($"Variable '{identifier}' is not defined.");
            }

            throw new InvalidOperationException($"Unexpected token near '{text[index..]}'.");
        }

        private string ParseString()
        {
            var quote = text[index++];
            var result = new List<char>();
            while (index < text.Length)
            {
                var ch = text[index++];
                if (ch == quote)
                {
                    return new string([.. result]);
                }

                if (ch == '\\' && index < text.Length)
                {
                    var escaped = text[index++];
                    result.Add(escaped switch
                    {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        _ => escaped
                    });
                }
                else
                {
                    result.Add(ch);
                }
            }

            throw new InvalidOperationException("Unterminated string literal.");
        }

        private double ParseNumber()
        {
            var start = index;
            while (index < text.Length && (char.IsDigit(text[index]) || text[index] == '.'))
            {
                index++;
            }

            var token = text[start..index];
            return TryDouble(token, out var value)
                ? value
                : throw new InvalidOperationException($"Invalid number '{token}'.");
        }

        private string ParseIdentifier()
        {
            var start = index;
            index++;
            while (index < text.Length && IsIdentifierPart(text[index]))
            {
                index++;
            }

            return text[start..index];
        }

        private bool Match(string token)
        {
            SkipWhitespace();
            if (!text.AsSpan(index).StartsWith(token, StringComparison.Ordinal))
            {
                return false;
            }

            index += token.Length;
            return true;
        }

        private char Peek() => index < text.Length ? text[index] : '\0';

        private void SkipWhitespace()
        {
            while (index < text.Length && char.IsWhiteSpace(text[index]))
            {
                index++;
            }
        }

        private static bool IsIdentifierStart(char value) =>
            value == '_' || value is >= 'A' and <= 'Z' || value is >= 'a' and <= 'z';

        private static bool IsIdentifierPart(char value) =>
            IsIdentifierStart(value) || value is >= '0' and <= '9';
    }

    private static double ToDouble(object? value)
    {
        if (value is null)
        {
            return 0d;
        }

        if (value is bool boolean)
        {
            return boolean ? 1d : 0d;
        }

        return TryDouble(Convert.ToString(value, CultureInfo.InvariantCulture), out var parsed)
            ? parsed
            : throw new InvalidOperationException($"Value '{value}' is not numeric.");
    }

    private static bool ToBoolean(object? value)
    {
        if (value is bool boolean)
        {
            return boolean;
        }

        if (value is null)
        {
            return false;
        }

        var text = Convert.ToString(value, CultureInfo.InvariantCulture);
        if (bool.TryParse(text, out var parsedBool))
        {
            return parsedBool;
        }

        return TryDouble(text, out var parsedDouble)
            ? parsedDouble != 0d
            : !string.IsNullOrWhiteSpace(text);
    }

    private static int Compare(object? left, object? right)
    {
        if (TryDouble(left, out var leftDouble) && TryDouble(right, out var rightDouble))
        {
            return leftDouble.CompareTo(rightDouble);
        }

        return string.Compare(
            Convert.ToString(left, CultureInfo.InvariantCulture),
            Convert.ToString(right, CultureInfo.InvariantCulture),
            StringComparison.Ordinal);
    }

    private static bool TryDouble(object? value, out double parsed) =>
        TryDouble(Convert.ToString(value, CultureInfo.InvariantCulture), out parsed);

    private static bool TryDouble(string? value, out double parsed)
    {
        if (double.TryParse(value, NumberStyles.Float | NumberStyles.AllowThousands, CultureInfo.InvariantCulture, out parsed)
            && double.IsFinite(parsed))
        {
            return true;
        }

        parsed = default;
        return false;
    }

    private static double RequireFinite(double value) =>
        double.IsFinite(value)
            ? value
            : throw new InvalidOperationException("Numeric result is not finite.");
}
