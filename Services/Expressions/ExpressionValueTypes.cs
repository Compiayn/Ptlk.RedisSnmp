using System.Globalization;
using Ptlk.RedisSnmp.Contracts.Snmp;

namespace Ptlk.RedisSnmp.Services.Expressions;

public static class ExpressionValueTypes
{
    public const string Double = "double";
    public const string Bool = "bool";
    public const string String = "string";
    private const string LegacyDecimal = "decimal";

    public static readonly string[] All = [Double, Bool, String];

    public static string Normalize(string? value)
    {
        if (string.Equals(value, LegacyDecimal, StringComparison.OrdinalIgnoreCase))
        {
            return Double;
        }

        if (string.Equals(value, SnmpValueTypes.Boolean, StringComparison.OrdinalIgnoreCase))
        {
            return Bool;
        }

        return All.FirstOrDefault(item => string.Equals(item, value, StringComparison.OrdinalIgnoreCase)) ?? Double;
    }

    public static string FromSnmpValueType(string? valueType)
    {
        if (string.Equals(valueType, SnmpValueTypes.Boolean, StringComparison.OrdinalIgnoreCase)
            || string.Equals(valueType, Bool, StringComparison.OrdinalIgnoreCase))
        {
            return Bool;
        }

        if (string.Equals(valueType, SnmpValueTypes.String, StringComparison.OrdinalIgnoreCase)
            || string.Equals(valueType, SnmpValueTypes.Oid, StringComparison.OrdinalIgnoreCase))
        {
            return String;
        }

        return Double;
    }

    public static string FromRedisPointType(string? type)
    {
        if (string.Equals(type, Bool, StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "boolean", StringComparison.OrdinalIgnoreCase))
        {
            return Bool;
        }

        if (string.Equals(type, String, StringComparison.OrdinalIgnoreCase)
            || string.Equals(type, "text", StringComparison.OrdinalIgnoreCase))
        {
            return String;
        }

        return Double;
    }

    public static object? ConvertFromPointValue(string? value, string valueType, string displayName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return Normalize(valueType) switch
        {
            Bool => ParseBool(value, displayName),
            String => value,
            _ => TryDouble(value, out var number)
                ? number
                : throw new InvalidOperationException($"{displayName} value '{value}' is not numeric.")
        };
    }

    public static string? ToPointValue(object? value, string valueType)
    {
        if (value is null)
        {
            return null;
        }

        return Normalize(valueType) switch
        {
            Bool => ToBool(value) ? "true" : "false",
            String => Convert.ToString(value, CultureInfo.InvariantCulture),
            _ => ToDouble(value).ToString("G17", CultureInfo.InvariantCulture)
        };
    }

    private static bool ParseBool(string value, string displayName)
    {
        if (bool.TryParse(value, out var boolean))
        {
            return boolean;
        }

        if (TryDouble(value, out var number))
        {
            return number != 0d;
        }

        throw new InvalidOperationException($"{displayName} value '{value}' is not boolean.");
    }

    private static bool ToBool(object value)
    {
        if (value is bool boolean)
        {
            return boolean;
        }

        if (TryDouble(Convert.ToString(value, CultureInfo.InvariantCulture), out var number))
        {
            return number != 0d;
        }

        return bool.TryParse(Convert.ToString(value, CultureInfo.InvariantCulture), out var parsed)
            ? parsed
            : throw new InvalidOperationException($"Value '{value}' is not boolean.");
    }

    private static double ToDouble(object value)
    {
        if (value is bool boolean)
        {
            return boolean ? 1d : 0d;
        }

        return TryDouble(Convert.ToString(value, CultureInfo.InvariantCulture), out var number)
            ? number
            : throw new InvalidOperationException($"Value '{value}' is not numeric.");
    }

    private static bool TryDouble(string? value, out double number)
    {
        if (double.TryParse(value, NumberStyles.Float | NumberStyles.AllowThousands, CultureInfo.InvariantCulture, out number)
            && double.IsFinite(number))
        {
            return true;
        }

        number = default;
        return false;
    }
}
