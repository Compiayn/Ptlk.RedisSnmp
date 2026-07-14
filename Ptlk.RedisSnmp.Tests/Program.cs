using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Components.Selection;
using Ptlk.RedisSnmp.Contracts.Mib;
using Ptlk.RedisSnmp.Contracts.Snmp;
using Ptlk.RedisSnmp.Contracts.Trap;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Models;
using Ptlk.RedisSnmp.Services.Commands;
using Ptlk.RedisSnmp.Services.Expressions;
using Ptlk.RedisSnmp.Services.ImportExport;
using Ptlk.RedisSnmp.Services.Logs;
using Ptlk.RedisSnmp.Services.Mib;
using Ptlk.RedisSnmp.Services.Paths;
using Ptlk.RedisSnmp.Services.Redis;
using Ptlk.RedisSnmp.Services.Snmp;
using Ptlk.RedisSnmp.Services.Startup;
using Ptlk.RedisSnmp.Services.Trap;

var tests = new (string Name, Func<Task> Run)[]
{
    ("source path normalization", RunSync(SourcePathNormalization)),
    ("snmp parser classifies success and noSuchInstance", RunSync(SnmpParserClassifiesResults)),
    ("snmp walk parser keeps oid syntax and values", RunSync(SnmpWalkParserKeepsOidSyntaxAndValues)),
    ("quality policy separates oid and agent failures", RunSync(QualityPolicySeparatesFailures)),
    ("snmp access controls read write capabilities", RunSync(SnmpAccessControlsReadWriteCapabilities)),
    ("net-snmp uses read community for get/walk and write community for set", NetSnmpUsesReadWriteCommunitiesAsync),
    ("credential edit preserves blank community secrets", CredentialEditPreservesBlankCommunitySecretsAsync),
    ("trap options default to standard port and credential publish mode", RunSync(TrapOptionsDefaultToStandardPortAndCredentialPublishMode)),
    ("trap credential community can be set preserved and cleared", TrapCredentialCommunityCanBeSetPreservedAndClearedAsync),
    ("trap security resolves agent host and validates configured credential", TrapSecurityResolvesAgentHostAndValidatesConfiguredCredentialAsync),
    ("trap publisher diagnostics records all traps and gates redis publish", TrapPublisherDiagnosticsRecordsAllTrapsAndGatesRedisPublishAsync),
    ("snmp walk uses default and requested operation timeout", SnmpWalkUsesDefaultAndRequestedOperationTimeoutAsync),
    ("runtime separates acquisition from redis output diagnostics", RunSync(RuntimeSeparatesDiagnostics)),
    ("mapping validation requires existing snmp point", MappingValidationRequiresExistingPointAsync),
    ("mapping validation accepts existing expression source", MappingValidationAcceptsExistingExpressionAsync),
    ("source path suggestions support load more pages", SourcePathSuggestionsSupportLoadMorePagesAsync),
    ("source path suggestions include expressions", SourcePathSuggestionsIncludeExpressionsAsync),
    ("expression runtime evaluates snmp cache", ExpressionRuntimeEvaluatesSnmpCacheAsync),
    ("mib import keeps numeric oid authoritative", MibImportKeepsNumericOidAsync),
    ("mib sets store raw files and refresh snapshots", MibSetsStoreRawFilesAndRefreshSnapshotsAsync),
    ("mib notification objects are stored for trap diagnostics", MibNotificationObjectsAreStoredForTrapDiagnosticsAsync),
    ("mib set snapshots include default mib bundle", MibSetSnapshotsIncludeDefaultMibBundleAsync),
    ("bundled default mib files refresh empty mib set", BundledDefaultMibFilesRefreshEmptyMibSetAsync),
    ("agent preserves mib context and point preserves mib metadata", AgentPreservesMibContextAndPointPreservesMibMetadataAsync),
    ("build point overwrite updates existing point", BuildPointOverwriteUpdatesExistingPointAsync),
    ("build point batch rejects invalid input atomically", BuildPointBatchRejectsInvalidInputAtomicallyAsync),
    ("extended selection supports file explorer modifiers", RunSync(ExtendedSelectionSupportsFileExplorerModifiers)),
    ("trap parser extracts channel oid", RunSync(TrapParserExtractsTrapOid)),
    ("trap parser reads streaming snmptrapd output", RunSync(TrapParserReadsStreamingSnmptrapdOutput)),
    ("csv import applies mappings last", CsvImportAppliesMappingsLastAsync),
    ("csv import resolves expression mappings after expression phase", CsvImportResolvesExpressionMappingsAfterExpressionPhaseAsync),
    ("csv import restores credential links and protected secrets", CsvImportRestoresCredentialLinksAndProtectedSecretsAsync),
    ("zip export imports csv and mib files", ZipExportImportsCsvAndMibFilesAsync)
};

foreach (var test in tests)
{
    await test.Run();
    Console.WriteLine($"PASS {test.Name}");
}

static Func<Task> RunSync(Action action) => () =>
{
    action();
    return Task.CompletedTask;
};

static void ExtendedSelectionSupportsFileExplorerModifiers()
{
    var keys = new[] { "a", "b", "c", "d", "e" };
    var selection = new ExtendedSelectionState(StringComparer.OrdinalIgnoreCase);

    selection.ApplyPointerSelection(keys, "b", range: false, additive: false);
    AssertEqual("b", string.Join(",", selection.SelectedKeys.OrderBy(key => key)));
    AssertEqual("b", selection.AnchorKey);

    selection.ApplyPointerSelection(keys, "d", range: false, additive: true);
    AssertEqual("b,d", string.Join(",", selection.SelectedKeys.OrderBy(key => key)));
    AssertEqual("d", selection.AnchorKey);

    selection.ApplyPointerSelection(keys, "b", range: true, additive: false);
    AssertEqual("b,c,d", string.Join(",", selection.SelectedKeys.OrderBy(key => key)));
    AssertEqual("d", selection.AnchorKey);

    selection.ApplyPointerSelection(keys, "a", range: true, additive: true);
    AssertEqual("a,b,c,d", string.Join(",", selection.SelectedKeys.OrderBy(key => key)));

    selection.SelectAll(keys);
    AssertEqual(5, selection.Count);
    selection.Clear();
    AssertEqual(0, selection.Count);
    AssertEqual<string?>(null, selection.AnchorKey);
}

static void SourcePathNormalization()
{
    var paths = new SnmpSourcePathService();
    AssertEqual("1.3.6.1.2.1.1.3.0", paths.NormalizeNumericOid(".1.3.6.1.2.1.1.3.0"));
    AssertEqual("snmp:agent1/1.3.6.1", paths.BuildPointSourcePath("agent1", ".1.3.6.1"));
    AssertThrows(() => paths.BuildPointSourcePath("bad/agent", "1.3"));
    AssertThrows(() => paths.NormalizeNumericOid("sysUpTime.0"));
}

static void SnmpParserClassifiesResults()
{
    var ok = SnmpClientService.ParseGetOrSet(
        "1.3.6.1",
        new NetSnmpProcessResult("snmpget", [], [], 0, ".1.3.6.1 = INTEGER: 42", "", TimeSpan.FromMilliseconds(5), false, null));
    AssertTrue(ok.Success, "Expected parse success.");
    AssertEqual("42", ok.Value);
    AssertEqual("INTEGER", ok.Syntax);

    var noSuch = SnmpClientService.ParseGetOrSet(
        "1.3.6.2",
        new NetSnmpProcessResult("snmpget", [], [], 0, ".1.3.6.2 = No Such Instance currently exists at this OID", "", TimeSpan.FromMilliseconds(5), false, null));
    AssertTrue(!noSuch.Success, "Expected noSuchInstance failure.");
    AssertEqual(SnmpOperationStatus.NoSuchInstance, noSuch.ErrorCode);
}

static void SnmpWalkParserKeepsOidSyntaxAndValues()
{
    var result = SnmpClientService.ParseWalk(
        new NetSnmpProcessResult(
            "snmpwalk",
            [],
            [],
            0,
            """
            .1.3.6.1.2.1.1.1.0 = STRING: Linux test host
            .1.3.6.1.2.1.1.3.0 = Timeticks: 12345
            """,
            "",
            TimeSpan.FromMilliseconds(5),
            false,
            null));

    AssertTrue(result.Success, "Walk parse should succeed.");
    AssertEqual(2, result.Items.Count);
    AssertEqual("1.3.6.1.2.1.1.1.0", result.Items[0].Oid);
    AssertEqual("STRING", result.Items[0].Syntax);
    AssertEqual("Linux test host", result.Items[0].Value);
    AssertEqual("Timeticks", result.Items[1].Syntax);
    AssertEqual("12345", result.Items[1].Value);
}

static void QualityPolicySeparatesFailures()
{
    var policy = new SnmpQualityPolicy();
    var point = new SnmpPointConfig { SourcePath = "snmp:a/1.3", NumericOid = "1.3" };
    var timeout = new SnmpGetResult(false, "1.3", null, null, "", SnmpOperationStatus.Timeout, "timeout");
    AssertTrue(policy.IsAgentLevelFailure(timeout), "Timeout should be agent-level.");

    var noSuch = new SnmpGetResult(false, "1.3", null, null, "", SnmpOperationStatus.NoSuchObject, "no such");
    AssertTrue(!policy.IsAgentLevelFailure(noSuch), "noSuchObject should be OID-level.");
    var result = policy.FromGetResult(point, noSuch);
    AssertEqual(SnmpQuality.Bad, result.Quality);
    AssertEqual("snmp:a/1.3", result.SourcePath);
}

static void SnmpAccessControlsReadWriteCapabilities()
{
    AssertTrue(SnmpAccessModes.CanRead(SnmpAccessModes.ReadOnly), "ro should be readable.");
    AssertTrue(SnmpAccessModes.CanRead(SnmpAccessModes.ReadWrite), "rw should be readable.");
    AssertTrue(!SnmpAccessModes.CanRead(SnmpAccessModes.WriteOnly), "wo should not be polled.");
    AssertTrue(!SnmpAccessModes.CanWrite(SnmpAccessModes.ReadOnly), "ro should not allow Set.");
    AssertTrue(SnmpAccessModes.CanWrite(SnmpAccessModes.ReadWrite), "rw should allow Set.");
    AssertTrue(SnmpAccessModes.CanWrite(SnmpAccessModes.WriteOnly), "wo should allow Set.");
}

static async Task NetSnmpUsesReadWriteCommunitiesAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var provider = new EphemeralDataProtectionProvider();
    var service = new SnmpCredentialService(database.Db, provider);
    var credential = await service.CreateOrUpdateAsync(
        new SnmpCredentialConfig { Name = "rw", Version = SnmpVersions.V2C },
        new SnmpCredentialSecrets("public", "private", null, null));
    var builder = new NetSnmpArgumentBuilder(service);
    var agent = new SnmpAgentConfig
    {
        AgentId = "a",
        DisplayName = "A",
        Host = "127.0.0.1",
        Port = 161,
        SnmpVersion = SnmpVersions.V2C,
        TimeoutMs = 5000,
        RetryCount = 1
    };

    var get = builder.BuildGet(agent, credential, "1.3.6.1");
    var walk = builder.BuildWalk(agent, credential, "1.3.6");
    var set = builder.BuildSet(agent, credential, "1.3.6.1", SnmpValueTypes.Integer, "1");

    AssertEqual("public", CommunityArgument(get));
    AssertEqual("public", CommunityArgument(walk));
    AssertEqual("private", CommunityArgument(set));
    AssertEqual("2c", VersionArgument(get));
    AssertEqual("2c", VersionArgument(walk));
    AssertEqual("2c", VersionArgument(set));
    AssertTrue(get.Arguments.Contains("-On"), "Get should request numeric OID output.");
    AssertTrue(walk.Arguments.Contains("-On"), "Walk should request numeric OID output.");
    AssertTrue(set.Arguments.Contains("-On"), "Set should request numeric OID output.");

    agent.SnmpVersion = SnmpVersions.V1;
    AssertEqual("1", VersionArgument(builder.BuildGet(agent, credential, "1.3.6.1")));
    agent.SnmpVersion = SnmpVersions.V3;
    AssertEqual("3", VersionArgument(builder.BuildGet(agent, null, "1.3.6.1")));
}

static async Task CredentialEditPreservesBlankCommunitySecretsAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var provider = new EphemeralDataProtectionProvider();
    var service = new SnmpCredentialService(database.Db, provider);
    var credential = await service.CreateOrUpdateAsync(
        new SnmpCredentialConfig { Name = "rw", Version = SnmpVersions.V2C },
        new SnmpCredentialSecrets("public", "private", null, null));

    var edited = await service.CreateOrUpdateAsync(
        new SnmpCredentialConfig { Id = credential.Id, Name = "rw-edited", Version = SnmpVersions.V2C },
        new SnmpCredentialSecrets(" ", "", null, null));
    var blankEditSecrets = service.RevealSecrets(edited);
    AssertEqual("public", blankEditSecrets.ReadCommunity);
    AssertEqual("private", blankEditSecrets.WriteCommunity);

    var readEdited = await service.CreateOrUpdateAsync(
        new SnmpCredentialConfig { Id = credential.Id, Name = "rw-edited", Version = SnmpVersions.V2C },
        new SnmpCredentialSecrets("public2", null, null, null));
    var readEditSecrets = service.RevealSecrets(readEdited);
    AssertEqual("public2", readEditSecrets.ReadCommunity);
    AssertEqual("private", readEditSecrets.WriteCommunity);

    var writeEdited = await service.CreateOrUpdateAsync(
        new SnmpCredentialConfig { Id = credential.Id, Name = "rw-edited", Version = SnmpVersions.V2C },
        new SnmpCredentialSecrets(null, "private2", null, null));
    var writeEditSecrets = service.RevealSecrets(writeEdited);
    AssertEqual("public2", writeEditSecrets.ReadCommunity);
    AssertEqual("private2", writeEditSecrets.WriteCommunity);
}

static void TrapOptionsDefaultToStandardPortAndCredentialPublishMode()
{
    var options = new TrapOptions();
    AssertEqual(162, options.ListenPort);
    AssertEqual(TrapPublishModes.Credential, options.PublishMode);
    AssertEqual(1000, options.BufferLimit);
}

static async Task TrapCredentialCommunityCanBeSetPreservedAndClearedAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var provider = new EphemeralDataProtectionProvider();
    var service = new SnmpTrapCredentialService(database.Db, provider);
    var credential = await service.CreateOrUpdateAsync(
        new SnmpTrapCredentialConfig { Name = "trap", Version = SnmpVersions.V2C },
        new SnmpTrapCredentialSecrets("trap-public", null, null));

    AssertEqual("trap-public", service.RevealSecrets(credential).Community);

    var preserved = await service.CreateOrUpdateAsync(
        new SnmpTrapCredentialConfig { Id = credential.Id, Name = "trap", Version = SnmpVersions.V2C, Enabled = true },
        new SnmpTrapCredentialSecrets(null, null, null));
    AssertEqual("trap-public", service.RevealSecrets(preserved).Community);

    var cleared = await service.CreateOrUpdateAsync(
        new SnmpTrapCredentialConfig { Id = credential.Id, Name = "trap", Version = SnmpVersions.V2C, Enabled = true },
        new SnmpTrapCredentialSecrets(null, null, null, ClearCommunity: true));
    AssertEqual(null, service.RevealSecrets(cleared).Community);
    AssertEqual(null, (await database.Db.SnmpTrapCredentialConfigs.AsNoTracking().SingleAsync()).ProtectedCommunity);
}

static async Task TrapSecurityResolvesAgentHostAndValidatesConfiguredCredentialAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var provider = new EphemeralDataProtectionProvider();
    var trapCredentials = new SnmpTrapCredentialService(database.Db, provider);
    var credential = await trapCredentials.CreateOrUpdateAsync(
        new SnmpTrapCredentialConfig { Name = "Trap Receiver", Version = SnmpVersions.V2C, Enabled = true },
        new SnmpTrapCredentialSecrets("trap-public", null, null));
    database.Db.SnmpAgentConfigs.Add(new SnmpAgentConfig
    {
        AgentId = "trap-a",
        DisplayName = "Trap A",
        Host = "10.0.0.7",
        TrapCredentialConfigId = credential.Id
    });
    await database.Db.SaveChangesAsync();

    var service = new TrapSecurityService(database.Db, trapCredentials);
    var accepted = await service.EvaluateAsync(new SnmpTrapMessage(
        "unknown",
        "10.0.0.7",
        "1.3.6",
        [],
        DateTimeOffset.UtcNow,
        "raw")
    {
        Version = SnmpVersions.V2C,
        Community = "trap-public"
    });
    AssertEqual(TrapAgentResolutionResults.Resolved, accepted.AgentResolutionResult);
    AssertEqual("trap-a", accepted.ResolvedAgentId);
    AssertEqual(TrapCredentialValidationResults.Accepted, accepted.CredentialValidationResult);

    var rejected = await service.EvaluateAsync(new SnmpTrapMessage(
        "unknown",
        "10.0.0.7",
        "1.3.6",
        [],
        DateTimeOffset.UtcNow,
        "raw")
    {
        Version = SnmpVersions.V2C,
        Community = "wrong"
    });
    AssertEqual(TrapCredentialValidationResults.Rejected, rejected.CredentialValidationResult);

    var unresolved = await service.EvaluateAsync(new SnmpTrapMessage("unknown", "10.0.0.8", "1.3.6", [], DateTimeOffset.UtcNow, "raw"));
    AssertEqual(TrapAgentResolutionResults.Unresolved, unresolved.AgentResolutionResult);
    AssertEqual(TrapCredentialValidationResults.NotApplicable, unresolved.CredentialValidationResult);
}

static async Task TrapPublisherDiagnosticsRecordsAllTrapsAndGatesRedisPublishAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var provider = new EphemeralDataProtectionProvider();
    var trapCredentials = new SnmpTrapCredentialService(database.Db, provider);
    var pubSub = new FakeRedisPubSubService();
    var options = Options.Create(new TrapOptions { PublishMode = TrapPublishModes.Credential });
    var publisher = new TrapEventPublisher(
        database.Db,
        new MibLookupService(database.Db),
        pubSub,
        new TrapSecurityService(database.Db, trapCredentials),
        options);

    var rejected = await publisher.PublishAsync(new SnmpTrapMessage(
        "unknown",
        "10.0.0.9",
        "1.3.6.1.6.3.1.1.5.3",
        [],
        DateTimeOffset.UtcNow,
        "raw"));

    AssertEqual("unknown", rejected.AgentId);
    AssertEqual(0, pubSub.Published.Count);
    AssertEqual(1, await database.Db.SnmpTrapLogEntries.CountAsync());
    var firstDiagnostic = await database.Db.SnmpTrapLogEntries.AsNoTracking().SingleAsync();
    AssertEqual(TrapAgentResolutionResults.Unresolved, firstDiagnostic.AgentResolutionResult);
    AssertEqual(TrapPublishResults.Skipped, firstDiagnostic.PublishResult);

    var trapCredential = await trapCredentials.CreateOrUpdateAsync(
        new SnmpTrapCredentialConfig { Name = "trap", Version = SnmpVersions.V2C, Enabled = true },
        new SnmpTrapCredentialSecrets("trap-public", null, null));
    database.Db.SnmpAgentConfigs.Add(new SnmpAgentConfig
    {
        AgentId = "a",
        DisplayName = "A",
        Host = "10.0.0.7",
        TrapCredentialConfigId = trapCredential.Id
    });
    database.Db.MibNodes.AddRange(
        new MibNode
        {
            VersionName = "test",
            NumericOid = "1.3.6.1.6.3.1.1.5.3",
            SymbolicName = "linkDown",
            ModuleName = "SNMPv2-MIB",
            NodeKind = "NOTIFICATION-TYPE",
            Active = true
        },
        new MibNode
        {
            VersionName = "test",
            NumericOid = "1.3.6.1.2.1.1.3",
            SymbolicName = "sysUpTime",
            ModuleName = "SNMPv2-MIB",
            Syntax = "TimeTicks",
            Active = true
        });
    await database.Db.SaveChangesAsync();

    var accepted = await publisher.PublishAsync(new SnmpTrapMessage(
        "unknown",
        "10.0.0.7",
        "1.3.6.1.6.3.1.1.5.3",
        [new SnmpTrapVarbind("1.3.6.1.2.1.1.3.0", "123", "Timeticks", null)],
        DateTimeOffset.UtcNow,
        "raw")
    {
        Version = SnmpVersions.V2C,
        Community = "trap-public"
    });

    AssertEqual("a", accepted.AgentId);
    AssertEqual(1, pubSub.Published.Count);
    AssertEqual("evt:snmp-trap:a:1.3.6.1.6.3.1.1.5.3", pubSub.Published[0].Channel);
    AssertEqual(2, await database.Db.SnmpTrapLogEntries.CountAsync());
    var publishedDiagnostic = await database.Db.SnmpTrapLogEntries.AsNoTracking().OrderBy(d => d.Id).LastAsync();
    AssertEqual(TrapCredentialValidationResults.Accepted, publishedDiagnostic.CredentialValidationResult);
    AssertEqual(TrapPublishResults.Published, publishedDiagnostic.PublishResult);
    var payloadJson = JsonSerializer.Serialize(pubSub.Published[0].Payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    using var payloadDoc = JsonDocument.Parse(payloadJson);
    var payload = payloadDoc.RootElement;
    AssertEqual("snmp.trap.received", payload.GetProperty("type").GetString() ?? "");
    AssertEqual(publishedDiagnostic.Id, payload.GetProperty("diagnosticId").GetInt32());
    AssertEqual("a", payload.GetProperty("agentId").GetString() ?? "");
    AssertEqual("1.3.6.1.6.3.1.1.5.3", payload.GetProperty("trapOid").GetString() ?? "");
    AssertEqual("SNMPv2-MIB::linkDown", payload.GetProperty("trapLabel").GetString() ?? "");
    AssertTrue(payload.TryGetProperty("timestamp", out var timestamp) && timestamp.ValueKind == JsonValueKind.Number, "Trap payload should include numeric timestamp.");
    var variables = payload.GetProperty("variables");
    AssertEqual(1, variables.GetArrayLength());
    var variable = variables[0];
    AssertEqual("1.3.6.1.2.1.1.3.0", variable.GetProperty("oid").GetString() ?? "");
    AssertEqual("123", variable.GetProperty("value").GetString() ?? "");
    AssertEqual("Timeticks", variable.GetProperty("syntax").GetString() ?? "");
    AssertEqual("SNMPv2-MIB::sysUpTime.0", variable.GetProperty("label").GetString() ?? "");

    await publisher.PublishAsync(new SnmpTrapMessage(
        "unknown",
        "10.0.0.7",
        "1.3.6.1.6.3.1.1.5.3",
        [],
        DateTimeOffset.UtcNow,
        "raw")
    {
        Version = SnmpVersions.V2C,
        Community = "wrong"
    });
    AssertEqual(1, pubSub.Published.Count);
    AssertEqual(3, await database.Db.SnmpTrapLogEntries.CountAsync());
}

static async Task SnmpWalkUsesDefaultAndRequestedOperationTimeoutAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var provider = new EphemeralDataProtectionProvider();
    var credentials = new SnmpCredentialService(database.Db, provider);
    var runner = new CapturingNetSnmpProcessRunner();
    var client = new SnmpClientService(
        new NetSnmpArgumentBuilder(credentials),
        runner,
        new LogService(database.Db),
        Options.Create(new SnmpRuntimeOptions
        {
            DefaultPollingRateMs = 1000,
            DefaultTimeoutMs = 5000,
            DefaultWalkTimeoutMs = 5000,
            DefaultRetryCount = 1
        }));
    var agent = new SnmpAgentConfig
    {
        AgentId = "a",
        DisplayName = "A",
        Host = "127.0.0.1",
        Port = 161,
        SnmpVersion = SnmpVersions.V2C,
        TimeoutMs = 5000,
        RetryCount = 1
    };

    await client.WalkAsync(agent, null, "1.3.6");
    await client.WalkAsync(agent, null, "1.3.6", operationTimeoutMs: 120000);

    AssertEqual(TimeSpan.FromMilliseconds(5000), runner.Timeouts[0]);
    AssertEqual(TimeSpan.FromMilliseconds(120000), runner.Timeouts[1]);
}

static void RuntimeSeparatesDiagnostics()
{
    var runtime = new RuntimeModeService();
    runtime.SetAcquisition(RuntimeSubsystemStatus.Normal, "SNMP acquisition is running.");
    runtime.SetRedisOutput(RuntimeSubsystemStatus.Normal, true, true, "Redis output is ready.");
    runtime.SetTrap(RuntimeSubsystemStatus.Normal, "Trap receiver is ready.");
    runtime.SetMib(RuntimeSubsystemStatus.Normal, "MIB ready.");
    AssertEqual(RuntimeMode.Normal, runtime.Current.Mode);

    runtime.ReportRedisOutputDiagnostic("test", "snmp:a/1.3", "point:a", "missing_key", "missing");
    AssertEqual(RuntimeMode.Degraded, runtime.Current.Mode);
    AssertEqual(RuntimeSubsystemStatus.Normal, runtime.Current.AcquisitionStatus);
    AssertEqual(RuntimeSubsystemStatus.Degraded, runtime.Current.RedisOutputStatus);
}

static async Task MappingValidationRequiresExistingPointAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var paths = new SnmpSourcePathService();
    var redis = new RedisConnectionFactory(Options.Create(new RedisOptions()), NullLogger<RedisConnectionFactory>.Instance);
    var service = new RedisMappingValidationService(database.Db, redis);

    var missing = await service.ValidateAsync("snmp:a/1.3", "point:site:a");
    AssertTrue(!missing.Success, "Missing point should fail validation.");

    database.Db.SnmpAgentConfigs.Add(new SnmpAgentConfig { AgentId = "a", DisplayName = "A", Host = "127.0.0.1" });
    await database.Db.SaveChangesAsync();
    var agent = await database.Db.SnmpAgentConfigs.FirstAsync();
    database.Db.SnmpPointConfigs.Add(new SnmpPointConfig
    {
        AgentConfigId = agent.Id,
        NumericOid = "1.3",
        SourcePath = paths.BuildPointSourcePath(agent.AgentId, "1.3"),
        ValueType = "string",
        Access = "ro"
    });
    await database.Db.SaveChangesAsync();

    var ok = await service.ValidateAsync("snmp:a/1.3", "point:site:a");
    AssertTrue(ok.Success, ok.Error ?? "Expected mapping validation success.");
}

static async Task MappingValidationAcceptsExistingExpressionAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var redis = new RedisConnectionFactory(Options.Create(new RedisOptions()), NullLogger<RedisConnectionFactory>.Instance);
    var service = new RedisMappingValidationService(database.Db, redis);

    var missing = await service.ValidateAsync("exp:Calc1", "point:site:calc1");
    AssertTrue(!missing.Success, "Missing expression should fail validation.");

    database.Db.ExpressionConfigs.Add(new ExpressionConfig
    {
        Name = "Calc1",
        Rw = "Ro",
        ValueType = ExpressionValueTypes.Double,
        ReadReturnParameter = "result",
        ReadScript = "result = 1;"
    });
    await database.Db.SaveChangesAsync();

    var ok = await service.ValidateAsync("exp:Calc1", "point:site:calc1");
    AssertTrue(ok.Success, ok.Error ?? "Expected expression mapping validation success.");
}

static async Task SourcePathSuggestionsSupportLoadMorePagesAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var paths = new SnmpSourcePathService();
    var agent = new SnmpAgentConfig { AgentId = "a", DisplayName = "A", Host = "127.0.0.1" };
    database.Db.SnmpAgentConfigs.Add(agent);
    await database.Db.SaveChangesAsync();

    for (var index = 1; index <= 3; index++)
    {
        var oid = $"1.3.6.1.{index}";
        database.Db.SnmpPointConfigs.Add(new SnmpPointConfig
        {
            AgentConfigId = agent.Id,
            MibLabel = $"Metric {index:00}",
            NumericOid = oid,
            SourcePath = paths.BuildPointSourcePath(agent.AgentId, oid),
            ValueType = "string",
            Access = "ro"
        });
    }

    await database.Db.SaveChangesAsync();

    var service = new PathSuggestionService(database.Db);
    var first = await service.SearchSnmpPointSuggestionsAsync("mEtRiC", limit: 2);
    AssertEqual(2, first.Items.Count);
    AssertTrue(first.HasMore, "First suggestion page should report more results.");
    AssertEqual(2, first.NextOffset);

    var second = await service.SearchSnmpPointSuggestionsAsync("Metric", limit: 2, offset: first.NextOffset);
    AssertEqual(1, second.Items.Count);
    AssertTrue(!second.HasMore, "Second suggestion page should be complete.");
    AssertEqual(3, second.NextOffset);
    AssertEqual("Metric 03", second.Items[0].MibLabel);

    var bySourcePath = await service.SearchSnmpPointSuggestionsAsync("SNMP:A/1.3.6.1.3", limit: 2);
    AssertEqual(1, bySourcePath.Items.Count);
    AssertEqual("Metric 03", bySourcePath.Items[0].MibLabel);
    AssertEqual("snmp:a/1.3.6.1.3", bySourcePath.Items[0].SourcePath);

    var byNumericOidOnly = await service.SearchSnmpPointSuggestionsAsync("1.3.6.1.3", limit: 2);
    AssertEqual(0, byNumericOidOnly.Items.Count);
}

static async Task SourcePathSuggestionsIncludeExpressionsAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    database.Db.ExpressionConfigs.Add(new ExpressionConfig
    {
        Name = "Calc1",
        Rw = "Ro",
        ValueType = ExpressionValueTypes.Double,
        ReadReturnParameter = "result",
        ReadScript = "result = 1;"
    });
    await database.Db.SaveChangesAsync();

    var service = new PathSuggestionService(database.Db);
    var byName = await service.SearchSnmpPointSuggestionsAsync("calc", limit: 5);
    AssertEqual(1, byName.Items.Count);
    AssertEqual("Expression", byName.Items[0].Kind);
    AssertEqual("exp:Calc1", byName.Items[0].SourcePath);

    var bySourcePath = await service.SearchSnmpPointSuggestionsAsync("EXP:CALC1", limit: 5);
    AssertEqual(1, bySourcePath.Items.Count);
    AssertEqual("exp:Calc1", bySourcePath.Items[0].SourcePath);
}

static async Task ExpressionRuntimeEvaluatesSnmpCacheAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var paths = new SnmpSourcePathService();
    var agent = new SnmpAgentConfig { AgentId = "a", DisplayName = "A", Host = "127.0.0.1" };
    database.Db.SnmpAgentConfigs.Add(agent);
    await database.Db.SaveChangesAsync();

    var sourcePath = paths.BuildPointSourcePath(agent.AgentId, "1.3.6.1");
    database.Db.SnmpPointConfigs.Add(new SnmpPointConfig
    {
        AgentConfigId = agent.Id,
        NumericOid = "1.3.6.1",
        SourcePath = sourcePath,
        ValueType = SnmpValueTypes.Integer,
        Access = SnmpAccessModes.ReadOnly
    });
    database.Db.ExpressionConfigs.Add(new ExpressionConfig
    {
        Name = "Calc1",
        Rw = "Ro",
        ValueType = ExpressionValueTypes.Double,
        ReadReturnParameter = "result",
        ReadScript = "result = current * 2;",
        Bindings =
        [
            new ExpressionBinding
            {
                ParameterName = "current",
                SourcePath = sourcePath
            }
        ]
    });
    await database.Db.SaveChangesAsync();

    var snmpCache = new SnmpValueCache();
    snmpCache.Set(new SnmpCachedValue(
        sourcePath,
        agent.AgentId,
        "1.3.6.1",
        "21",
        SnmpQuality.Good,
        DateTimeOffset.UtcNow,
        "21",
        null,
        null));
    var expressionCache = new ExpressionValueCache();
    var runtime = CreateExpressionRuntime(database.Db, snmpCache, expressionCache);

    var result = (await runtime.EvaluateReadableExpressionsAsync()).Single();
    AssertEqual("exp:Calc1", result.SourcePath);
    AssertEqual("42", result.Value);
    AssertEqual(SnmpQuality.Good, result.Quality);
    AssertEqual("42", expressionCache.Get("exp:Calc1")?.Value);
}

static async Task MibImportKeepsNumericOidAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var runtime = new RuntimeModeService();
    var importer = new MibImportService(database.Db, new SnmpSourcePathService(), runtime);
    var lookup = new MibLookupService(database.Db);

    var result = await importer.ImportTextAsync("v1", "test.csv", "1.3.6.1.2,sysDescr,SNMPv2-MIB,OCTET STRING,read-only,System description", true);
    AssertTrue(result.Success, "MIB import should succeed.");
    var node = await lookup.LookupAsync(".1.3.6.1.2");
    AssertEqual("1.3.6.1.2", node?.NumericOid);
    AssertEqual("sysDescr", node?.SymbolicName);
}

static async Task MibSetsStoreRawFilesAndRefreshSnapshotsAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var runtime = new RuntimeModeService();
    var paths = new SnmpSourcePathService();
    using var mibStorage = new TemporaryDirectory();
    using var defaultMibStorage = new TemporaryDirectory();
    var service = new MibSetService(
        database.Db,
        paths,
        runtime,
        Options.Create(new NetSnmpOptions
        {
            MibDirectory = mibStorage.Path,
            DefaultMibDirectory = defaultMibStorage.Path
        }));
    var lookup = new MibLookupService(database.Db);

    var vendorA = await service.CreateOrUpdateAsync(new MibSet { Name = "Vendor A", Status = MibSetStatuses.Available });
    var vendorB = await service.CreateOrUpdateAsync(new MibSet { Name = "Vendor B", Status = MibSetStatuses.Available });
    AssertEqual(MibSetStatuses.Draft, vendorA.Status);
    database.Db.MibSets.Add(new MibSet { Name = "Legacy Validated", Status = "validated" });
    await database.Db.SaveChangesAsync();
    var legacyValidated = await database.Db.MibSets.AsNoTracking().SingleAsync(s => s.Name == "Legacy Validated");
    AssertEqual(MibSetStatuses.SnapshotStale, (await service.GetAsync(legacyValidated.Id))?.Status);

    var fileA = await service.UploadMibFileAsync(vendorA.Id, "a", TextStream("""
        VENDOR-A-MIB DEFINITIONS ::= BEGIN
        IMPORTS enterprises FROM SNMPv2-SMI;
        vendorA MODULE-IDENTITY
            ::= { enterprises 1000 }
        statusA OBJECT-TYPE
            SYNTAX INTEGER
            MAX-ACCESS read-only
            DESCRIPTION "A status"
            ::= { vendorA 1 }
        END
        """));
    AssertTrue(File.Exists(fileA.StoredPath), "Uploaded MIB file should be stored on disk.");
    AssertEqual(MibFileValidationStatuses.Parsed, fileA.ValidationStatus);
    AssertEqual(MibSetStatuses.SnapshotStale, (await service.GetAsync(vendorA.Id))?.Status);

    await service.UploadMibFileAsync(vendorB.Id, "b.mib", TextStream("""
        VENDOR-B-MIB DEFINITIONS ::= BEGIN
        IMPORTS enterprises FROM SNMPv2-SMI;
        vendorB MODULE-IDENTITY
            ::= { enterprises 1000 }
        statusB OBJECT-TYPE
            SYNTAX INTEGER
            MAX-ACCESS read-only
            DESCRIPTION "B status"
            ::= { vendorB 1 }
        END
        """));

    AssertEqual(null, (await lookup.LookupAsync(vendorA.Id, "1.3.6.1.4.1.1000.1"))?.SymbolicName);
    var refreshA = await service.ValidateAndUpdateSnapshotAsync(vendorA.Id);
    var refreshB = await service.ValidateAndUpdateSnapshotAsync(vendorB.Id);
    AssertTrue(refreshA.Success, "Vendor A snapshot refresh should succeed.");
    AssertTrue(refreshB.Success, "Vendor B snapshot refresh should succeed.");
    AssertEqual(MibSetStatuses.Available, (await service.GetAsync(vendorA.Id))?.Status);
    AssertTrue((await service.ListFilesAsync(vendorA.Id)).All(f => f.ValidationStatus == MibFileValidationStatuses.Validated), "Snapshot refresh should mark files as validated.");

    var a = await lookup.LookupAsync(vendorA.Id, "1.3.6.1.4.1.1000.1.0");
    var b = await lookup.LookupAsync(vendorB.Id, "1.3.6.1.4.1.1000.1");
    AssertEqual("statusA", a?.SymbolicName);
    AssertEqual("statusB", b?.SymbolicName);

    await service.UploadMibFileAsync(vendorA.Id, "a-conflict.mib", TextStream("""
        VENDOR-A-CONFLICT-MIB DEFINITIONS ::= BEGIN
        IMPORTS enterprises FROM SNMPv2-SMI;
        vendorAConflict MODULE-IDENTITY
            ::= { enterprises 1000 }
        statusA2 OBJECT-TYPE
            SYNTAX INTEGER
            MAX-ACCESS read-only
            DESCRIPTION "A status conflict"
            ::= { vendorAConflict 1 }
        END
        """));
    AssertEqual(MibSetStatuses.SnapshotStale, (await service.GetAsync(vendorA.Id))?.Status);
    var failedRefresh = await service.ValidateAndUpdateSnapshotAsync(vendorA.Id);
    AssertTrue(!failedRefresh.Success, "Conflicting snapshot refresh should fail.");
    var issues = await service.ListIssuesAsync(vendorA.Id);
    AssertTrue(issues.Any(i => i.Code == "oid_label_conflict" && i.Severity == MibValidationSeverities.Error), "Expected set-local OID label conflict.");
    AssertEqual(MibSetStatuses.SnapshotStale, (await service.GetAsync(vendorA.Id))?.Status);
    var unchanged = await lookup.LookupAsync(vendorA.Id, "1.3.6.1.4.1.1000.1");
    AssertEqual("statusA", unchanged?.SymbolicName);

    var vendorAFiles = await service.ListFilesAsync(vendorA.Id);
    await service.DeleteFileAsync(vendorA.Id, vendorAFiles.Single(f => f.FileName == "a-conflict.mib").Id);
    var recoveredRefresh = await service.ValidateAndUpdateSnapshotAsync(vendorA.Id);
    AssertTrue(recoveredRefresh.Success, "Snapshot refresh should succeed after removing the conflict.");
    var recoveredIssues = await service.ListIssuesAsync(vendorA.Id);
    AssertTrue(recoveredIssues.All(i => i.Code != "oid_label_conflict"), "Validation issues should only contain the latest validation result.");

    var refAgent = new SnmpAgentConfig
    {
        AgentId = "ref-agent",
        DisplayName = "Referenced Agent",
        Host = "127.0.0.1",
        SnmpVersion = SnmpVersions.V2C,
        PreferredMibSetId = vendorA.Id
    };
    database.Db.SnmpAgentConfigs.Add(refAgent);
    await database.Db.SaveChangesAsync();
    database.Db.SnmpPointConfigs.Add(new SnmpPointConfig
    {
        AgentConfigId = refAgent.Id,
        NumericOid = "1.3.6.1.4.1.1000.1",
        SourcePath = paths.BuildPointSourcePath(refAgent.AgentId, "1.3.6.1.4.1.1000.1"),
        ValueType = SnmpValueTypes.Integer,
        Access = SnmpAccessModes.ReadOnly
    });
    await database.Db.SaveChangesAsync();
    var blockedDelete = await service.DeleteAsync(vendorA.Id);
    AssertTrue(!blockedDelete.Success, "Referenced MIB set delete should be blocked.");
    AssertTrue(blockedDelete.References.Any(r => r.Kind == "agent" && r.Name == "ref-agent"), "Delete result should include the blocking agent reference.");
    AssertTrue(!blockedDelete.References.Any(r => r.Kind == "point"), "Delete result should only include agent references.");
    AssertTrue(await service.GetAsync(vendorA.Id) is not null, "Referenced MIB set should remain after blocked delete.");

    var files = await service.ListFilesAsync(vendorB.Id);
    await service.DeleteFileAsync(vendorB.Id, files.Single().Id);
    AssertEqual(MibSetStatuses.SnapshotStale, (await service.GetAsync(vendorB.Id))?.Status);
    var clearRefresh = await service.ValidateAndUpdateSnapshotAsync(vendorB.Id);
    AssertTrue(clearRefresh.Success, "Empty set snapshot refresh should succeed and clear nodes.");
    var deleted = await lookup.LookupAsync(vendorB.Id, "1.3.6.1.4.1.1000.1");
    AssertEqual(null, deleted?.SymbolicName);

    var vendorC = await service.CreateOrUpdateAsync(new MibSet { Name = "Vendor C" });
    var fileC = await service.UploadMibFileAsync(vendorC.Id, "c", TextStream("""
        VENDOR-C-MIB DEFINITIONS ::= BEGIN
        IMPORTS enterprises FROM SNMPv2-SMI;
        vendorC MODULE-IDENTITY
            ::= { enterprises 1001 }
        statusC OBJECT-TYPE
            SYNTAX INTEGER
            MAX-ACCESS read-only
            DESCRIPTION "C status"
            ::= { vendorC 1 }
        END
        """));
    var deletedSet = await service.DeleteAsync(vendorC.Id);
    AssertTrue(deletedSet.Success, "Unreferenced MIB set delete should succeed.");
    AssertTrue(await service.GetAsync(vendorC.Id) is null, "Deleted MIB set should be removed.");
    AssertTrue(!File.Exists(fileC.StoredPath), "Deleting a MIB set should remove stored files.");
}

static async Task MibSetSnapshotsIncludeDefaultMibBundleAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var runtime = new RuntimeModeService();
    var paths = new SnmpSourcePathService();
    using var mibStorage = new TemporaryDirectory();
    using var defaultMibStorage = new TemporaryDirectory();
    var defaultGroup = System.IO.Path.Combine(defaultMibStorage.Path, "recommended-first-batch");
    Directory.CreateDirectory(defaultGroup);
    var defaultMibPath = System.IO.Path.Combine(defaultGroup, "DEFAULT-BASE-MIB");
    await File.WriteAllTextAsync(defaultMibPath, """
        DEFAULT-BASE-MIB DEFINITIONS ::= BEGIN
        IMPORTS enterprises FROM SNMPv2-SMI;

        defaultBase MODULE-IDENTITY
            DESCRIPTION "Default base"
            ::= { enterprises 4242 }

        baseStatus OBJECT-TYPE
            SYNTAX INTEGER
            MAX-ACCESS read-only
            DESCRIPTION "Base status"
            ::= { defaultBase 1 }
        END
        """);

    var service = new MibSetService(
        database.Db,
        paths,
        runtime,
        Options.Create(new NetSnmpOptions
        {
            MibDirectory = mibStorage.Path,
            DefaultMibDirectory = defaultMibStorage.Path
        }));
    var lookup = new MibLookupService(database.Db);

    var defaults = await service.ListDefaultMibFilesAsync();
    AssertEqual(1, defaults.Count);
    AssertEqual("recommended-first-batch/DEFAULT-BASE-MIB", defaults[0].RelativePath);
    AssertTrue((await service.ReadDefaultMibFileContentAsync(defaults[0].RelativePath)).Contains("DEFAULT-BASE-MIB", StringComparison.Ordinal), "Default MIB content should be readable.");

    var set = await service.CreateOrUpdateAsync(new MibSet { Name = "Vendor With Defaults" });
    await service.UploadMibFileAsync(set.Id, "vendor.mib", TextStream("""
        VENDOR-WITH-DEFAULTS-MIB DEFINITIONS ::= BEGIN
        IMPORTS defaultBase FROM DEFAULT-BASE-MIB;

        vendorStatus OBJECT-TYPE
            SYNTAX INTEGER
            MAX-ACCESS read-only
            DESCRIPTION "Vendor status"
            ::= { defaultBase 2 }
        END
        """));

    var refresh = await service.ValidateAndUpdateSnapshotAsync(set.Id);
    AssertTrue(refresh.Success, "Snapshot refresh should include default and uploaded MIB files.");
    AssertEqual("baseStatus", (await lookup.LookupAsync(set.Id, "1.3.6.1.4.1.4242.1"))?.SymbolicName);
    AssertEqual("vendorStatus", (await lookup.LookupAsync(set.Id, "1.3.6.1.4.1.4242.2"))?.SymbolicName);
    AssertEqual(1, (await service.ListFilesAsync(set.Id)).Count);
}

static async Task MibNotificationObjectsAreStoredForTrapDiagnosticsAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var runtime = new RuntimeModeService();
    var paths = new SnmpSourcePathService();
    using var mibStorage = new TemporaryDirectory();
    using var defaultMibStorage = new TemporaryDirectory();
    var service = new MibSetService(
        database.Db,
        paths,
        runtime,
        Options.Create(new NetSnmpOptions
        {
            MibDirectory = mibStorage.Path,
            DefaultMibDirectory = defaultMibStorage.Path
        }));

    var set = await service.CreateOrUpdateAsync(new MibSet { Name = "Trap MIB" });
    await service.UploadMibFileAsync(set.Id, "trap.mib", TextStream("""
        VENDOR-TRAP-MIB DEFINITIONS ::= BEGIN
        IMPORTS enterprises FROM SNMPv2-SMI;

        vendorTrap MODULE-IDENTITY
            DESCRIPTION "Trap root"
            ::= { enterprises 5010 }

        alarmObject OBJECT-TYPE
            SYNTAX INTEGER
            MAX-ACCESS read-only
            DESCRIPTION "Alarm object"
            ::= { vendorTrap 1 }

        alarmTrap NOTIFICATION-TYPE
            OBJECTS { alarmObject }
            DESCRIPTION "Alarm trap"
            ::= { vendorTrap 2 }
        END
        """));

    var refresh = await service.ValidateAndUpdateSnapshotAsync(set.Id);
    AssertTrue(refresh.Success, "Trap MIB snapshot refresh should succeed.");
    var trapNode = await database.Db.MibNodes
        .AsNoTracking()
        .SingleAsync(n => n.MibSetId == set.Id && n.SymbolicName == "alarmTrap");
    AssertEqual("NOTIFICATION-TYPE", trapNode.NodeKind);
    var expected = await database.Db.MibNotificationObjects.AsNoTracking().SingleAsync();
    AssertEqual(trapNode.Id, expected.NotificationMibNodeId);
    AssertEqual("alarmObject", expected.ObjectSymbol);
    AssertEqual("1.3.6.1.4.1.5010.1", expected.ObjectOid);
}

static async Task BundledDefaultMibFilesRefreshEmptyMibSetAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var runtime = new RuntimeModeService();
    var paths = new SnmpSourcePathService();
    using var mibStorage = new TemporaryDirectory();
    var service = new MibSetService(
        database.Db,
        paths,
        runtime,
        Options.Create(new NetSnmpOptions { MibDirectory = mibStorage.Path }));
    var lookup = new MibLookupService(database.Db);

    var defaults = await service.ListDefaultMibFilesAsync();
    AssertTrue(defaults.Count >= 10, "Bundled default MIB files should be copied to output.");

    var set = await service.CreateOrUpdateAsync(new MibSet { Name = "Defaults Only" });
    var refresh = await service.ValidateAndUpdateSnapshotAsync(set.Id);
    AssertTrue(refresh.Success, "Empty set snapshot refresh should include bundled default MIB files.");
    AssertTrue(refresh.NodeCount > 0, "Bundled default MIB files should produce snapshot nodes.");
    AssertEqual(0, (await service.ListFilesAsync(set.Id)).Count);
    AssertEqual("sysDescr", (await lookup.LookupAsync(set.Id, "1.3.6.1.2.1.1.1"))?.SymbolicName);
}

static async Task AgentPreservesMibContextAndPointPreservesMibMetadataAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var paths = new SnmpSourcePathService();
    var runtime = new RuntimeModeService();
    using var mibStorage = new TemporaryDirectory();
    using var defaultMibStorage = new TemporaryDirectory();
    var mibSets = new MibSetService(
        database.Db,
        paths,
        runtime,
        Options.Create(new NetSnmpOptions
        {
            MibDirectory = mibStorage.Path,
            DefaultMibDirectory = defaultMibStorage.Path
        }));
    var set = await mibSets.CreateOrUpdateAsync(new MibSet { Name = "Preferred", Status = MibSetStatuses.Available });

    var agents = new SnmpAgentService(
        database.Db,
        paths,
        Options.Create(new SnmpRuntimeOptions
        {
            DefaultPollingRateMs = 1000,
            DefaultTimeoutMs = 5000,
            DefaultWalkTimeoutMs = 5000,
            DefaultRetryCount = 1
        }));
    var agent = await agents.CreateOrUpdateAsync(new SnmpAgentConfig
    {
        AgentId = "a",
        DisplayName = "A",
        Host = "127.0.0.1",
        SnmpVersion = SnmpVersions.V2C,
        PreferredMibSetId = set.Id
    });

    var points = new SnmpPointService(database.Db, paths);
    await points.CreateOrUpdateAsync(new SnmpPointConfig
    {
        AgentConfigId = agent.Id,
        NumericOid = "1.3.6.1",
        ValueType = SnmpValueTypes.Integer,
        Access = SnmpAccessModes.ReadOnly,
        MibLabel = "statusA",
        MibModule = "VENDOR-A-MIB",
        MibSyntax = "INTEGER",
        MibAccess = "read-only",
        MibDescription = "Status A"
    });

    var savedAgent = await database.Db.SnmpAgentConfigs.AsNoTracking().FirstAsync();
    var savedPoint = await database.Db.SnmpPointConfigs.AsNoTracking().FirstAsync();
    AssertEqual(set.Id, savedAgent.PreferredMibSetId);
    AssertEqual("statusA", savedPoint.MibLabel);
    AssertEqual("VENDOR-A-MIB", savedPoint.MibModule);
}

static async Task BuildPointOverwriteUpdatesExistingPointAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var paths = new SnmpSourcePathService();
    var agent = new SnmpAgentConfig { AgentId = "overwrite-agent", DisplayName = "Overwrite Agent", Host = "127.0.0.1" };
    database.Db.SnmpAgentConfigs.Add(agent);
    await database.Db.SaveChangesAsync();

    var service = new SnmpPointService(database.Db, paths);
    var original = await service.CreateOrUpdateAsync(new SnmpPointConfig
    {
        AgentConfigId = agent.Id,
        NumericOid = "1.3.6.1.2.1.1.3.0",
        ValueType = SnmpValueTypes.Integer,
        Access = SnmpAccessModes.ReadOnly,
        MibLabel = "oldLabel",
        MibModule = "OLD-MIB"
    });

    var savedBatch = await service.CreateOrOverwriteBatchAsync(
    [
        new SnmpPointConfig
        {
            AgentConfigId = agent.Id,
            NumericOid = ".1.3.6.1.2.1.1.3.0",
            ValueType = SnmpValueTypes.Timeticks,
            Access = SnmpAccessModes.ReadWrite,
            MibLabel = "sysUpTimeInstance",
            MibModule = "DISMAN-EVENT-MIB"
        },
        new SnmpPointConfig
        {
            AgentConfigId = agent.Id,
            NumericOid = "1.3.6.1.2.1.1.5.0",
            ValueType = SnmpValueTypes.String,
            Access = SnmpAccessModes.ReadOnly,
            MibLabel = "sysName"
        }
    ]);
    var overwritten = savedBatch[0];

    AssertEqual(original.Id, overwritten.Id);
    AssertEqual(2, await database.Db.SnmpPointConfigs.CountAsync());
    var saved = await database.Db.SnmpPointConfigs.AsNoTracking().SingleAsync(point => point.Id == original.Id);
    AssertEqual(SnmpValueTypes.Timeticks, saved.ValueType);
    AssertEqual(SnmpAccessModes.ReadWrite, saved.Access);
    AssertEqual("sysUpTimeInstance", saved.MibLabel);
    AssertEqual("DISMAN-EVENT-MIB", saved.MibModule);
}

static async Task BuildPointBatchRejectsInvalidInputAtomicallyAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var agent = new SnmpAgentConfig { AgentId = "atomic-agent", DisplayName = "Atomic Agent", Host = "127.0.0.1" };
    database.Db.SnmpAgentConfigs.Add(agent);
    await database.Db.SaveChangesAsync();
    var service = new SnmpPointService(database.Db, new SnmpSourcePathService());

    var rejected = false;
    try
    {
        await service.CreateOrOverwriteBatchAsync(
        [
            new SnmpPointConfig
            {
                AgentConfigId = agent.Id,
                NumericOid = "1.3.6.1.2.1.1.1.0",
                ValueType = SnmpValueTypes.String,
                Access = SnmpAccessModes.ReadOnly
            },
            new SnmpPointConfig
            {
                AgentConfigId = agent.Id,
                NumericOid = "1.3.6.1.2.1.1.2.0",
                ValueType = SnmpValueTypes.Oid,
                Access = "invalid"
            }
        ]);
    }
    catch (InvalidOperationException)
    {
        rejected = true;
    }

    AssertTrue(rejected, "Invalid batch should be rejected.");
    AssertEqual(0, await database.Db.SnmpPointConfigs.CountAsync());
}

static void TrapParserExtractsTrapOid()
{
    var parser = new TrapParser(new SnmpSourcePathService());
    var trap = parser.Parse("""
        source=10.0.0.8
        .1.3.6.1.6.3.1.1.4.1.0 = OID: .1.3.6.1.6.3.1.1.5.3
        .1.3.6.1.2.1.1.3.0 = Timeticks: 123
        """);

    AssertEqual("10.0.0.8", trap.SourceAddress);
    AssertEqual("1.3.6.1.6.3.1.1.5.3", trap.TrapOid);
    AssertEqual(2, trap.Varbinds.Count);
}

static void TrapParserReadsStreamingSnmptrapdOutput()
{
    var parser = new TrapParser(new SnmpSourcePathService());
    var trap = parser.Parse("source=UDP: [10.0.0.7]:49152->[192.168.1.10]:162|security=trap-public|.1.3.6.1.2.1.1.3.0 = Timeticks: 123|.1.3.6.1.6.3.1.1.4.1.0 = OID: .1.3.6.1.6.3.1.1.5.3");

    AssertEqual("10.0.0.7", trap.SourceAddress);
    AssertEqual(49152, trap.SourcePort);
    AssertEqual("trap-public", trap.Community ?? "");
    AssertEqual("1.3.6.1.6.3.1.1.5.3", trap.TrapOid);
    AssertEqual(2, trap.Varbinds.Count);
    AssertEqual("1.3.6.1.2.1.1.3.0", trap.Varbinds[0].Oid);
    AssertEqual("123", trap.Varbinds[0].Value ?? "");
    AssertEqual("Timeticks", trap.Varbinds[0].Syntax ?? "");
}

static async Task CsvImportAppliesMappingsLastAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var paths = new SnmpSourcePathService();
    var redis = new RedisConnectionFactory(Options.Create(new RedisOptions()), NullLogger<RedisConnectionFactory>.Instance);
    var mapping = new RedisMappingValidationService(database.Db, redis);
    var csv = new CsvConfigService(database.Db, Options.Create(new ImportExportOptions()), paths, mapping, new ExpressionValidationService());
    var content = string.Join(
        Environment.NewLine,
        "kind,name,version,agent_id,display_name,host,port,snmp_version,numeric_oid,value_type,access,mapping_source_path,mapping_redis_key,trap_oid,description,mib_label",
        "agent,,,a,Agent A,127.0.0.1,161,v2c,,,,,,,,",
        "point,,,a,,,,,1.3.6.1,string,ro,,,,Metric 1",
        "mapping,,,,,,,,,,,snmp:a/1.3.6.1,point:site:snmp:p1,,,"
    );

    await using var stream = new MemoryStream(Encoding.UTF8.GetBytes(content));
    var result = await csv.ImportAsync(stream);
    AssertEqual(0, result.Errors.Count);
    AssertEqual(1, await database.Db.SnmpAgentConfigs.CountAsync());
    AssertEqual(1, await database.Db.SnmpPointConfigs.CountAsync());
    AssertEqual(1, await database.Db.RedisMappings.CountAsync());

    await using var exported = await csv.ExportAsync();
    using var reader = new StreamReader(exported, Encoding.UTF8);
    var exportedContent = await reader.ReadToEndAsync();
    AssertTrue(!exportedContent.Contains("poll_enabled", StringComparison.OrdinalIgnoreCase), "Export should not include point polling flag.");
    AssertTrue(!exportedContent.Contains("set_enabled", StringComparison.OrdinalIgnoreCase), "Export should not include point Set flag.");
    AssertTrue(!exportedContent.Contains("point_polling_rate_ms", StringComparison.OrdinalIgnoreCase), "Export should not include point polling override.");
    AssertTrue(!exportedContent.Contains("mib_set_used", StringComparison.OrdinalIgnoreCase), "Export should not include point MIB set association.");
    AssertTrue(!exportedContent.Contains("point_name", StringComparison.OrdinalIgnoreCase), "Export should not include the old point_name column.");
}

static async Task CsvImportResolvesExpressionMappingsAfterExpressionPhaseAsync()
{
    await using var database = await TestDatabase.CreateAsync();
    var paths = new SnmpSourcePathService();
    var redis = new RedisConnectionFactory(Options.Create(new RedisOptions()), NullLogger<RedisConnectionFactory>.Instance);
    var mapping = new RedisMappingValidationService(database.Db, redis);
    var csv = new CsvConfigService(database.Db, Options.Create(new ImportExportOptions()), paths, mapping, new ExpressionValidationService());
    var rows = new[]
    {
        CsvLine(
            "kind",
            "expression_name",
            "expression_rw",
            "expression_value_type",
            "read_return_parameter",
            "read_script",
            "binding_parameter_name",
            "binding_source_path",
            "mapping_source_path",
            "mapping_redis_key"),
        CsvLine("mapping", "", "", "", "", "", "", "", "exp:Calc1", "point:site:calc1"),
        CsvLine("expression", "Calc1", "Ro", "double", "result", "result = 1;", "", "", "", "")
    };

    await using var stream = new MemoryStream(Encoding.UTF8.GetBytes(string.Join(Environment.NewLine, rows)));
    var result = await csv.ImportAsync(stream);
    AssertEqual(0, result.Errors.Count);
    AssertEqual(1, await database.Db.ExpressionConfigs.CountAsync());
    AssertEqual(1, await database.Db.RedisMappings.CountAsync(m => m.SourcePath == "exp:Calc1"));

    await using var exported = await csv.ExportAsync();
    using var reader = new StreamReader(exported, Encoding.UTF8);
    var exportedContent = await reader.ReadToEndAsync();
    var expressionIndex = exportedContent.IndexOf("expression,", StringComparison.Ordinal);
    var mappingIndex = exportedContent.IndexOf("mapping,", StringComparison.Ordinal);
    AssertTrue(expressionIndex >= 0, "Expression row should be exported.");
    AssertTrue(mappingIndex >= 0, "Mapping row should be exported.");
    AssertTrue(expressionIndex < mappingIndex, "Expression rows should be exported before mapping rows.");
}

static async Task CsvImportRestoresCredentialLinksAndProtectedSecretsAsync()
{
    await using var sourceDatabase = await TestDatabase.CreateAsync();
    await using var targetDatabase = await TestDatabase.CreateAsync();
    var paths = new SnmpSourcePathService();
    var protector = new EphemeralDataProtectionProvider();
    var sourceCredentials = new SnmpCredentialService(sourceDatabase.Db, protector);
    var sourceCredential = await sourceCredentials.CreateOrUpdateAsync(
        new SnmpCredentialConfig
        {
            Name = "Plant RW",
            Version = SnmpVersions.V3,
            SecurityName = "plant-user",
            SecurityLevel = "authPriv",
            AuthProtocol = "SHA",
            PrivProtocol = "AES"
        },
        new SnmpCredentialSecrets(
            "source-public-secret-for-roundtrip",
            "source-private-secret-for-roundtrip",
            "source-auth-secret-for-roundtrip",
            "source-priv-secret-for-roundtrip"));
    var sourceTrapCredentials = new SnmpTrapCredentialService(sourceDatabase.Db, protector);
    var sourceTrapCredential = await sourceTrapCredentials.CreateOrUpdateAsync(
        new SnmpTrapCredentialConfig
        {
            Name = "Plant Trap",
            Version = SnmpVersions.V2C,
            Enabled = true
        },
        new SnmpTrapCredentialSecrets("source-trap-secret-for-roundtrip", null, null));

    sourceDatabase.Db.SnmpAgentConfigs.Add(new SnmpAgentConfig
    {
        AgentId = "plant-a",
        DisplayName = "Plant A",
        Host = "127.0.0.1",
        SnmpVersion = SnmpVersions.V3,
        CredentialConfigId = sourceCredential.Id,
        TrapCredentialConfigId = sourceTrapCredential.Id
    });
    await sourceDatabase.Db.SaveChangesAsync();

    var sourceCsv = CreateCsvConfigService(sourceDatabase.Db, paths);
    await using var exported = await sourceCsv.ExportAsync();
    using var exportedReader = new StreamReader(exported, Encoding.UTF8);
    var exportedContent = await exportedReader.ReadToEndAsync();
    AssertTrue(exportedContent.Contains("credential_name", StringComparison.OrdinalIgnoreCase), "Export should include agent credential references.");
    AssertTrue(exportedContent.Contains("trap_credential_name", StringComparison.OrdinalIgnoreCase), "Export should include agent trap credential references.");
    AssertTrue(exportedContent.Contains("protected_read_community", StringComparison.OrdinalIgnoreCase), "Export should include protected read community.");
    AssertTrue(exportedContent.Contains("protected_trap_community", StringComparison.OrdinalIgnoreCase), "Export should include protected trap community.");
    AssertTrue(exportedContent.Contains(sourceCredential.ProtectedReadCommunity ?? "", StringComparison.Ordinal), "Export should include the protected read community value.");
    AssertTrue(exportedContent.Contains(sourceTrapCredential.ProtectedCommunity ?? "", StringComparison.Ordinal), "Export should include the protected trap community value.");
    AssertTrue(!exportedContent.Contains("source-public-secret-for-roundtrip", StringComparison.Ordinal), "Export should not include plaintext read community.");
    AssertTrue(!exportedContent.Contains("source-trap-secret-for-roundtrip", StringComparison.Ordinal), "Export should not include plaintext trap community.");
    AssertTrue(!exportedContent.Contains("source-auth-secret-for-roundtrip", StringComparison.Ordinal), "Export should not include plaintext auth password.");

    var targetCsv = CreateCsvConfigService(targetDatabase.Db, paths);
    await using var importStream = TextStream(exportedContent);
    var result = await targetCsv.ImportAsync(importStream);
    AssertEqual(0, result.Errors.Count);

    var targetCredential = await targetDatabase.Db.SnmpCredentialConfigs.AsNoTracking().SingleAsync();
    var targetTrapCredential = await targetDatabase.Db.SnmpTrapCredentialConfigs.AsNoTracking().SingleAsync();
    var targetAgent = await targetDatabase.Db.SnmpAgentConfigs.AsNoTracking().SingleAsync();
    var targetCredentials = new SnmpCredentialService(targetDatabase.Db, protector);
    var targetSecrets = targetCredentials.RevealSecrets(targetCredential);
    var targetTrapCredentials = new SnmpTrapCredentialService(targetDatabase.Db, protector);
    var targetTrapSecrets = targetTrapCredentials.RevealSecrets(targetTrapCredential);
    AssertEqual(targetCredential.Id, targetAgent.CredentialConfigId);
    AssertEqual(targetTrapCredential.Id, targetAgent.TrapCredentialConfigId);
    AssertEqual("source-public-secret-for-roundtrip", targetSecrets.ReadCommunity);
    AssertEqual("source-private-secret-for-roundtrip", targetSecrets.WriteCommunity);
    AssertEqual("source-auth-secret-for-roundtrip", targetSecrets.AuthPassword);
    AssertEqual("source-priv-secret-for-roundtrip", targetSecrets.PrivPassword);
    AssertEqual("source-trap-secret-for-roundtrip", targetTrapSecrets.Community);

    await using var legacyDatabase = await TestDatabase.CreateAsync();
    var legacyCredentials = new SnmpCredentialService(legacyDatabase.Db, protector);
    var legacyCredential = await legacyCredentials.CreateOrUpdateAsync(
        new SnmpCredentialConfig { Name = "Keep", Version = SnmpVersions.V2C },
        new SnmpCredentialSecrets("keep-read", "keep-write", null, null));
    legacyDatabase.Db.SnmpAgentConfigs.Add(new SnmpAgentConfig
    {
        AgentId = "legacy",
        DisplayName = "Legacy",
        Host = "10.0.0.1",
        SnmpVersion = SnmpVersions.V2C,
        CredentialConfigId = legacyCredential.Id
    });
    await legacyDatabase.Db.SaveChangesAsync();

    var legacyCsv = CreateCsvConfigService(legacyDatabase.Db, paths);
    var legacyContent = string.Join(
        Environment.NewLine,
        "kind,name,version,agent_id,display_name,host,port,snmp_version,description",
        "credential,Keep,v2c,,,,,,updated credential",
        "agent,,,legacy,Legacy Updated,10.0.0.8,162,v2c,updated agent"
    );

    await using var legacyStream = TextStream(legacyContent);
    var legacyResult = await legacyCsv.ImportAsync(legacyStream);
    AssertEqual(0, legacyResult.Errors.Count);
    var legacyAgent = await legacyDatabase.Db.SnmpAgentConfigs.AsNoTracking().SingleAsync(a => a.AgentId == "legacy");
    var keptCredential = await legacyDatabase.Db.SnmpCredentialConfigs.AsNoTracking().SingleAsync(c => c.Name == "Keep");
    var legacySecrets = legacyCredentials.RevealSecrets(keptCredential);
    AssertEqual(legacyCredential.Id, legacyAgent.CredentialConfigId);
    AssertEqual("keep-read", legacySecrets.ReadCommunity);
    AssertEqual("keep-write", legacySecrets.WriteCommunity);
}

static async Task ZipExportImportsCsvAndMibFilesAsync()
{
    await using var sourceDatabase = await TestDatabase.CreateAsync();
    await using var targetDatabase = await TestDatabase.CreateAsync();
    var paths = new SnmpSourcePathService();
    var protector = new EphemeralDataProtectionProvider();
    using var sourceMibStorage = new TemporaryDirectory();
    using var targetMibStorage = new TemporaryDirectory();
    using var emptyDefaultMibs = new TemporaryDirectory();
    var sourceMibSets = new MibSetService(
        sourceDatabase.Db,
        paths,
        new RuntimeModeService(),
        Options.Create(new NetSnmpOptions
        {
            MibDirectory = sourceMibStorage.Path,
            DefaultMibDirectory = emptyDefaultMibs.Path
        }));
    var targetMibSets = new MibSetService(
        targetDatabase.Db,
        paths,
        new RuntimeModeService(),
        Options.Create(new NetSnmpOptions
        {
            MibDirectory = targetMibStorage.Path,
            DefaultMibDirectory = emptyDefaultMibs.Path
        }));

    var mibSet = await sourceMibSets.CreateOrUpdateAsync(new MibSet { Name = "Vendor ZIP" });
    var sourceCredentials = new SnmpCredentialService(sourceDatabase.Db, protector);
    var credential = await sourceCredentials.CreateOrUpdateAsync(
        new SnmpCredentialConfig { Name = "ZIP RW", Version = SnmpVersions.V2C },
        new SnmpCredentialSecrets("zip-public", "zip-private", null, null));
    await sourceMibSets.UploadMibFileAsync(mibSet.Id, "vendor-zip.mib", TextStream("""
        VENDOR-ZIP-MIB DEFINITIONS ::= BEGIN
        IMPORTS enterprises FROM SNMPv2-SMI;
        vendorZip MODULE-IDENTITY
            ::= { enterprises 7777 }
        zipStatus OBJECT-TYPE
            SYNTAX INTEGER
            MAX-ACCESS read-only
            DESCRIPTION "ZIP status"
            ::= { vendorZip 1 }
        END
        """));

    var agent = new SnmpAgentConfig
    {
        AgentId = "zip-agent",
        DisplayName = "ZIP Agent",
        Host = "127.0.0.1",
        SnmpVersion = SnmpVersions.V2C,
        CredentialConfigId = credential.Id,
        PreferredMibSetId = mibSet.Id
    };
    sourceDatabase.Db.SnmpAgentConfigs.Add(agent);
    await sourceDatabase.Db.SaveChangesAsync();
    sourceDatabase.Db.SnmpPointConfigs.Add(new SnmpPointConfig
    {
        AgentConfigId = agent.Id,
        NumericOid = "1.3.6.1.4.1.7777.1",
        SourcePath = paths.BuildPointSourcePath(agent.AgentId, "1.3.6.1.4.1.7777.1"),
        ValueType = SnmpValueTypes.Integer,
        Access = SnmpAccessModes.ReadOnly,
        MibLabel = "zipStatus"
    });
    sourceDatabase.Db.RedisMappings.Add(new RedisMapping
    {
        SourcePath = "snmp:zip-agent/1.3.6.1.4.1.7777.1",
        RedisKey = "point:site:zipStatus"
    });
    await sourceDatabase.Db.SaveChangesAsync();

    var sourceMapping = new RedisMappingValidationService(
        sourceDatabase.Db,
        new RedisConnectionFactory(Options.Create(new RedisOptions()), NullLogger<RedisConnectionFactory>.Instance));
    var sourceCsv = new CsvConfigService(sourceDatabase.Db, Options.Create(new ImportExportOptions()), paths, sourceMapping, new ExpressionValidationService());
    var sourceZip = new ZipConfigService(sourceCsv, sourceDatabase.Db, sourceMibSets, Options.Create(new ImportExportOptions()));
    await using var bundle = await sourceZip.ExportAsync();

    var targetMapping = new RedisMappingValidationService(
        targetDatabase.Db,
        new RedisConnectionFactory(Options.Create(new RedisOptions()), NullLogger<RedisConnectionFactory>.Instance));
    var targetCsv = new CsvConfigService(targetDatabase.Db, Options.Create(new ImportExportOptions()), paths, targetMapping, new ExpressionValidationService());
    var targetZip = new ZipConfigService(targetCsv, targetDatabase.Db, targetMibSets, Options.Create(new ImportExportOptions()));
    using var uploadedBundle = new AsyncOnlyReadStream(((MemoryStream)bundle).ToArray());
    var result = await targetZip.ImportAsync(uploadedBundle);

    AssertEqual(0, result.Errors.Count);
    AssertEqual(1, await targetDatabase.Db.MibSets.CountAsync());
    AssertEqual(1, await targetDatabase.Db.MibFiles.CountAsync());
    AssertEqual(1, await targetDatabase.Db.SnmpAgentConfigs.CountAsync());
    AssertEqual(1, await targetDatabase.Db.SnmpPointConfigs.CountAsync());
    AssertEqual(1, await targetDatabase.Db.RedisMappings.CountAsync());

    var importedSet = await targetDatabase.Db.MibSets.AsNoTracking().SingleAsync();
    var importedFile = await targetDatabase.Db.MibFiles.AsNoTracking().SingleAsync();
    AssertEqual("Vendor ZIP", importedSet.Name);
    AssertEqual("vendor-zip.mib", importedFile.FileName);
    AssertTrue(File.Exists(importedFile.StoredPath), "Imported MIB file should be restored to target storage.");
    var importedAgent = await targetDatabase.Db.SnmpAgentConfigs.AsNoTracking().SingleAsync();
    var importedCredential = await targetDatabase.Db.SnmpCredentialConfigs.AsNoTracking().SingleAsync();
    var targetCredentials = new SnmpCredentialService(targetDatabase.Db, protector);
    var importedSecrets = targetCredentials.RevealSecrets(importedCredential);
    AssertEqual(importedSet.Id, importedAgent.PreferredMibSetId);
    AssertEqual(importedCredential.Id, importedAgent.CredentialConfigId);
    AssertEqual("zip-public", importedSecrets.ReadCommunity);
    AssertEqual("zip-private", importedSecrets.WriteCommunity);
}

static void AssertEqual<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
    {
        throw new InvalidOperationException($"Expected {expected}, got {actual}.");
    }
}

static void AssertTrue(bool value, string message)
{
    if (!value)
    {
        throw new InvalidOperationException(message);
    }
}

static void AssertThrows(Action action)
{
    try
    {
        action();
    }
    catch
    {
        return;
    }

    throw new InvalidOperationException("Expected an exception.");
}

static MemoryStream TextStream(string content) =>
    new(Encoding.UTF8.GetBytes(content));

static string CsvLine(params string[] values) => string.Join(",", values);

static CsvConfigService CreateCsvConfigService(AppDbContext db, SnmpSourcePathService paths)
{
    var redis = new RedisConnectionFactory(Options.Create(new RedisOptions()), NullLogger<RedisConnectionFactory>.Instance);
    var mapping = new RedisMappingValidationService(db, redis);
    return new CsvConfigService(db, Options.Create(new ImportExportOptions()), paths, mapping, new ExpressionValidationService());
}

static ExpressionRuntimeService CreateExpressionRuntime(
    AppDbContext db,
    SnmpValueCache snmpCache,
    ExpressionValueCache expressionCache)
{
    var redisOptions = Options.Create(new RedisOptions());
    var redisSnmpOptions = Options.Create(new RedisSnmpOptions());
    var redis = new RedisConnectionFactory(redisOptions, NullLogger<RedisConnectionFactory>.Instance);
    var runtime = new RuntimeModeService();
    var pubSub = new RedisPubSubService(redis, NullLogger<RedisPubSubService>.Instance);
    var pointState = new RedisPointStateService(redis, pubSub, redisSnmpOptions, runtime);
    var ownership = new RedisPointOwnershipService(redis, redisSnmpOptions, runtime, NullLogger<RedisPointOwnershipService>.Instance);
    var commands = new CommandExecutionService(
        new ThrowingScopeFactory(),
        pubSub,
        ownership,
        redisSnmpOptions,
        NullLogger<CommandExecutionService>.Instance);
    var log = new LogService(db);
    var dispatcher = new CommandDispatcherService(commands, log, redisSnmpOptions);

    return new ExpressionRuntimeService(
        db,
        new ExpressionScriptEngine(),
        pointState,
        dispatcher,
        commands,
        log,
        snmpCache,
        expressionCache,
        redisSnmpOptions);
}

static string CommunityArgument(NetSnmpCommandArguments command)
{
    var index = command.Arguments.ToList().IndexOf("-c");
    if (index < 0 || index + 1 >= command.Arguments.Count)
    {
        throw new InvalidOperationException("Command did not include a community argument.");
    }

    return command.Arguments[index + 1];
}

static string VersionArgument(NetSnmpCommandArguments command)
{
    var index = command.Arguments.ToList().IndexOf("-v");
    if (index < 0 || index + 1 >= command.Arguments.Count)
    {
        throw new InvalidOperationException("Command did not include a version argument.");
    }

    return command.Arguments[index + 1];
}

sealed class TestDatabase : IAsyncDisposable
{
    private readonly SqliteConnection _connection;

    private TestDatabase(SqliteConnection connection, AppDbContext db)
    {
        _connection = connection;
        Db = db;
    }

    public AppDbContext Db { get; }

    public static async Task<TestDatabase> CreateAsync()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .Options;
        var db = new AppDbContext(options);
        await db.Database.EnsureCreatedAsync();
        return new TestDatabase(connection, db);
    }

    public async ValueTask DisposeAsync()
    {
        await Db.DisposeAsync();
        await _connection.DisposeAsync();
    }
}

sealed class TemporaryDirectory : IDisposable
{
    public TemporaryDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ptlk-redis-snmp-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
        catch
        {
        }
    }
}

sealed class CapturingNetSnmpProcessRunner : INetSnmpProcessRunner
{
    public List<TimeSpan> Timeouts { get; } = [];

    public Task<NetSnmpProcessResult> RunAsync(
        NetSnmpCommandArguments command,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        Timeouts.Add(timeout);
        return Task.FromResult(new NetSnmpProcessResult(
            command.Tool,
            command.Arguments,
            command.RedactedArguments,
            0,
            ".1.3.6.1 = INTEGER: 1",
            "",
            TimeSpan.FromMilliseconds(1),
            false,
            null));
    }
}

sealed class FakeRedisPubSubService : IRedisPubSubService
{
    public List<(string Channel, object Payload)> Published { get; } = [];

    public Task PublishAsync(string channel, object payload, CancellationToken cancellationToken = default)
    {
        Published.Add((channel, payload));
        return Task.CompletedTask;
    }
}

sealed class ThrowingScopeFactory : IServiceScopeFactory
{
    public IServiceScope CreateScope() =>
        throw new NotSupportedException("This test scope factory should not be used.");
}

sealed class AsyncOnlyReadStream(byte[] content) : Stream
{
    private readonly MemoryStream _inner = new(content);

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("Synchronous reads are not supported.");

    public override ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default) =>
        _inner.ReadAsync(buffer, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException();

    public override void SetLength(long value) =>
        throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
