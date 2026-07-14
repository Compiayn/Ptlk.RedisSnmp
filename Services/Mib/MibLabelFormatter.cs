using Ptlk.RedisSnmp.Contracts.Mib;

namespace Ptlk.RedisSnmp.Services.Mib;

public static class MibLabelFormatter
{
    public static string? FormatSymbolicOid(MibLookupResult? lookup, string? numericOid)
    {
        if (string.IsNullOrWhiteSpace(lookup?.SymbolicName))
        {
            return null;
        }

        var symbolicName = lookup.SymbolicName.Trim();
        var requestedOid = NormalizeNumericOid(numericOid);
        var resolvedOid = NormalizeNumericOid(lookup.NumericOid);

        if (requestedOid is not null
            && resolvedOid is not null
            && requestedOid.StartsWith(resolvedOid + ".", StringComparison.Ordinal))
        {
            symbolicName += requestedOid[resolvedOid.Length..];
        }

        return symbolicName;
    }

    public static string? FormatQualifiedSymbolicOid(MibLookupResult? lookup, string? numericOid)
    {
        var symbolicOid = FormatSymbolicOid(lookup, numericOid);
        if (symbolicOid is null)
        {
            return null;
        }

        return string.IsNullOrWhiteSpace(lookup?.ModuleName)
            ? symbolicOid
            : $"{lookup.ModuleName.Trim()}::{symbolicOid}";
    }

    private static string? NormalizeNumericOid(string? numericOid)
    {
        if (string.IsNullOrWhiteSpace(numericOid))
        {
            return null;
        }

        var normalized = numericOid.Trim().TrimStart('.');
        return normalized.Length > 0 && normalized.All(ch => char.IsDigit(ch) || ch == '.')
            ? normalized
            : null;
    }
}
