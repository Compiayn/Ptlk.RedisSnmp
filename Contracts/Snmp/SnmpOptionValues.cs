namespace Ptlk.RedisSnmp.Contracts.Snmp;

public static class SnmpVersions
{
    public const string V1 = "v1";
    public const string V2C = "v2c";
    public const string V3 = "v3";
}

public static class SnmpSecurityLevels
{
    public const string NoAuthNoPriv = "noAuthNoPriv";
    public const string AuthNoPriv = "authNoPriv";
    public const string AuthPriv = "authPriv";
}

public static class SnmpAccessModes
{
    public const string ReadOnly = "ro";
    public const string ReadWrite = "rw";
    public const string WriteOnly = "wo";
}

public static class SnmpValueTypes
{
    public const string String = "string";
    public const string Integer = "integer";
    public const string Double = "double";
    public const string Boolean = "boolean";
    public const string Timeticks = "timeticks";
    public const string Oid = "oid";
}

public static class SnmpOperationStatus
{
    public const string Success = "success";
    public const string Timeout = "timeout";
    public const string AuthFailure = "auth_failure";
    public const string NoSuchObject = "no_such_object";
    public const string NoSuchInstance = "no_such_instance";
    public const string NoSuchName = "no_such_name";
    public const string DecodeFailed = "decode_failed";
    public const string ToolMissing = "tool_missing";
    public const string Failed = "failed";
}
