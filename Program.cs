using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Ptlk.RedisSnmp.Components;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Services.Browser;
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
using Ptlk.RedisSnmp.Services.Ui;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

builder.Services.AddRedisSnmpOptions(builder.Configuration);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Data Source=/data/redis-snmp.db";
var dataProtectionKeysPath = builder.Configuration["DataProtection:KeysPath"]
    ?? (builder.Environment.IsDevelopment() ? "data-protection-keys" : "/data/data-protection-keys");
Directory.CreateDirectory(dataProtectionKeysPath);

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionKeysPath));

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(connectionString)
           .UseSnakeCaseNamingConvention());

builder.Services.AddSingleton<RuntimeModeService>();
builder.Services.AddSingleton<RedisConnectionFactory>();
builder.Services.AddSingleton<RedisPubSubService>();
builder.Services.AddSingleton<IRedisPubSubService>(sp => sp.GetRequiredService<RedisPubSubService>());
builder.Services.AddSingleton<RedisPointOwnershipService>();
builder.Services.AddSingleton<SnmpSourcePathService>();
builder.Services.AddSingleton<SnmpValueCache>();
builder.Services.AddSingleton<ExpressionValueCache>();
builder.Services.AddSingleton<SnmpQualityPolicy>();
builder.Services.AddSingleton<INetSnmpProcessRunner, NetSnmpProcessRunner>();

builder.Services.AddScoped<RedisPointStateService>();
builder.Services.AddScoped<RedisMappingValidationService>();
builder.Services.AddScoped<RedisKeySuggestionService>();
builder.Services.AddScoped<SnmpCredentialService>();
builder.Services.AddScoped<SnmpTrapCredentialService>();
builder.Services.AddScoped<SnmpAgentService>();
builder.Services.AddScoped<SnmpPointService>();
builder.Services.AddScoped<NetSnmpArgumentBuilder>();
builder.Services.AddScoped<SnmpClientService>();
builder.Services.AddScoped<CommandDispatcherService>();
builder.Services.AddScoped<CommandExecutionService>();
builder.Services.AddSingleton<ExpressionScriptEngine>();
builder.Services.AddScoped<ExpressionService>();
builder.Services.AddScoped<ExpressionValidationService>();
builder.Services.AddScoped<ExpressionRuntimeService>();
builder.Services.AddScoped<BrowserSnapshotService>();
builder.Services.AddScoped<LogService>();
builder.Services.AddScoped<PathSuggestionService>();
builder.Services.AddScoped<MibSetService>();
builder.Services.AddScoped<MibImportService>();
builder.Services.AddScoped<MibLookupService>();
builder.Services.AddScoped<MibExportService>();
builder.Services.AddScoped<TrapParser>();
builder.Services.AddScoped<TrapSecurityService>();
builder.Services.AddScoped<TrapEventPublisher>();
builder.Services.AddScoped<CsvConfigService>();
builder.Services.AddScoped<ZipConfigService>();
builder.Services.AddScoped<ScreenAlertService>();

builder.Services.AddHostedService<StartupGateService>();
builder.Services.AddHostedService<RedisPointOwnershipHostedService>();
builder.Services.AddHostedService<RedisSnmpStatusService>();
builder.Services.AddHostedService<DeviceCommandSubscriptionService>();
builder.Services.AddHostedService<SnmpPollingHostedService>();
builder.Services.AddHostedService<ExpressionRuntimeHostedService>();
builder.Services.AddHostedService<NetSnmpTrapReceiverService>();

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.MigrateAsync();
}

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapGet("/healthz", (RuntimeModeService runtime) => Results.Ok(runtime.Current));

app.Run();
