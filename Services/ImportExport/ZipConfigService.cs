using System.IO.Compression;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;

namespace Ptlk.RedisSnmp.Services.ImportExport;

public sealed class ZipConfigService(
    CsvConfigService csv,
    IOptions<ImportExportOptions> options)
{
    public async Task<Stream> ExportAsync(CancellationToken cancellationToken = default)
    {
        var output = new MemoryStream();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            var entry = archive.CreateEntry("redis-snmp-config.csv");
            await using var entryStream = entry.Open();
            await using var csvStream = await csv.ExportAsync(cancellationToken);
            await csvStream.CopyToAsync(entryStream, cancellationToken);
        }
        output.Position = 0;
        return output;
    }

    public async Task<CsvImportResult> ImportAsync(Stream zipStream, CancellationToken cancellationToken = default)
    {
        if (zipStream.Length > options.Value.ZipFileLimitBytes)
        {
            return new CsvImportResult(0, [$"ZIP size exceeds {options.Value.ZipFileLimitBytes} bytes."]);
        }

        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read, leaveOpen: true);
        var entry = archive.Entries.FirstOrDefault(e => e.Name.EndsWith(".csv", StringComparison.OrdinalIgnoreCase));
        if (entry is null)
        {
            return new CsvImportResult(0, ["ZIP does not contain a CSV file."]);
        }
        if (entry.Length > options.Value.SingleCsvLimitBytes)
        {
            return new CsvImportResult(0, [$"CSV entry exceeds {options.Value.SingleCsvLimitBytes} bytes."]);
        }

        await using var entryStream = entry.Open();
        var buffer = new MemoryStream();
        await entryStream.CopyToAsync(buffer, cancellationToken);
        buffer.Position = 0;
        return await csv.ImportAsync(buffer, cancellationToken);
    }
}
