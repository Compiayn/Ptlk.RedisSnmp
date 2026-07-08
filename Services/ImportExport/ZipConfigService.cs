using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Ptlk.RedisSnmp.Configuration;
using Ptlk.RedisSnmp.Data;
using Ptlk.RedisSnmp.Services.Mib;

namespace Ptlk.RedisSnmp.Services.ImportExport;

public sealed class ZipConfigService(
    CsvConfigService csv,
    AppDbContext db,
    MibSetService mibSets,
    IOptions<ImportExportOptions> options)
{
    private const string CsvEntryName = "redis-snmp-config.csv";
    private const string ManifestEntryName = "manifest.json";

    public async Task<Stream> ExportAsync(CancellationToken cancellationToken = default)
    {
        var output = new MemoryStream();
        var manifestFiles = new List<ZipMibFileManifestEntry>();

        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            var configEntry = archive.CreateEntry(CsvEntryName);
            await using (var entryStream = configEntry.Open())
            await using (var csvStream = await csv.ExportAsync(cancellationToken))
            {
                await csvStream.CopyToAsync(entryStream, cancellationToken);
            }

            var files = await db.MibFiles
                .AsNoTracking()
                .Include(file => file.MibSet)
                .Where(file => file.MibSet != null && file.StoredPath != null)
                .OrderBy(file => file.MibSet!.Name)
                .ThenBy(file => file.FileName)
                .ToListAsync(cancellationToken);

            foreach (var file in files)
            {
                var setName = file.MibSet!.Name;
                var entryName = $"mibs/{file.MibSetId}-{SafeEntrySegment(setName)}/{SafeEntrySegment(file.FileName)}";
                var fileEntry = archive.CreateEntry(entryName);
                var content = await mibSets.ReadFileContentAsync(file.MibSetId, file.Id, cancellationToken);
                await using var entryStream = fileEntry.Open();
                await using var writer = new StreamWriter(entryStream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), leaveOpen: true);
                await writer.WriteAsync(content.AsMemory(), cancellationToken);

                manifestFiles.Add(new ZipMibFileManifestEntry(setName, file.FileName, entryName));
            }

            var manifest = new ZipConfigManifest(1, manifestFiles);
            var manifestEntry = archive.CreateEntry(ManifestEntryName);
            await using var manifestStream = manifestEntry.Open();
            await JsonSerializer.SerializeAsync(manifestStream, manifest, cancellationToken: cancellationToken);
        }

        output.Position = 0;
        return output;
    }

    public async Task<CsvImportResult> ImportAsync(Stream zipStream, CancellationToken cancellationToken = default)
    {
        if (zipStream.CanSeek && zipStream.Length > options.Value.ZipFileLimitBytes)
        {
            return new CsvImportResult(0, [$"ZIP size exceeds {options.Value.ZipFileLimitBytes} bytes."]);
        }

        using var zipBuffer = await BufferAsync(
            zipStream,
            options.Value.ZipFileLimitBytes,
            "ZIP",
            cancellationToken);
        using var archive = new ZipArchive(zipBuffer, ZipArchiveMode.Read, leaveOpen: true);
        var extractedBytes = archive.Entries.Where(e => !string.IsNullOrWhiteSpace(e.Name)).Sum(e => e.Length);
        if (extractedBytes > options.Value.ZipExtractedLimitBytes)
        {
            return new CsvImportResult(0, [$"ZIP extracted size exceeds {options.Value.ZipExtractedLimitBytes} bytes."]);
        }

        var configEntry = archive.GetEntry(CsvEntryName)
                          ?? archive.Entries.FirstOrDefault(e => e.Name.EndsWith(".csv", StringComparison.OrdinalIgnoreCase));
        if (configEntry is null)
        {
            return new CsvImportResult(0, ["ZIP does not contain a configuration CSV file."]);
        }
        if (configEntry.Length > options.Value.SingleCsvLimitBytes)
        {
            return new CsvImportResult(0, [$"CSV entry exceeds {options.Value.SingleCsvLimitBytes} bytes."]);
        }

        await using var configStream = configEntry.Open();
        var buffer = new MemoryStream();
        await configStream.CopyToAsync(buffer, cancellationToken);
        buffer.Position = 0;
        var csvResult = await csv.ImportAsync(buffer, cancellationToken);
        if (csvResult.Errors.Count > 0)
        {
            return csvResult;
        }

        var manifest = await ReadManifestAsync(archive, cancellationToken);
        if (manifest is null || manifest.MibFiles.Count == 0)
        {
            return csvResult;
        }

        var errors = new List<string>();
        var pendingFiles = new List<(int MibSetId, string FileName, ZipArchiveEntry Entry)>();
        foreach (var file in manifest.MibFiles)
        {
            if (string.IsNullOrWhiteSpace(file.MibSetName)
                || string.IsNullOrWhiteSpace(file.FileName)
                || string.IsNullOrWhiteSpace(file.EntryName))
            {
                errors.Add("MIB file manifest entry is incomplete.");
                continue;
            }

            var entry = archive.GetEntry(file.EntryName);
            if (entry is null)
            {
                errors.Add($"MIB file '{file.EntryName}' is missing from the ZIP.");
                continue;
            }

            var setId = await db.MibSets
                .AsNoTracking()
                .Where(set => set.Name == file.MibSetName)
                .Select(set => (int?)set.Id)
                .FirstOrDefaultAsync(cancellationToken);
            if (setId is null)
            {
                errors.Add($"MIB set '{file.MibSetName}' was not found after importing the CSV.");
                continue;
            }

            pendingFiles.Add((setId.Value, file.FileName, entry));
        }

        if (errors.Count > 0)
        {
            return new CsvImportResult(csvResult.ImportedRows, errors);
        }

        var importedFiles = 0;
        foreach (var file in pendingFiles)
        {
            try
            {
                await using var entryStream = file.Entry.Open();
                await mibSets.UploadMibFileAsync(file.MibSetId, file.FileName, entryStream, cancellationToken);
                importedFiles++;
            }
            catch (Exception ex)
            {
                errors.Add($"{file.FileName}: {ex.Message}");
            }
        }

        return new CsvImportResult(csvResult.ImportedRows + importedFiles, errors);
    }

    private static async Task<ZipConfigManifest?> ReadManifestAsync(
        ZipArchive archive,
        CancellationToken cancellationToken)
    {
        var entry = archive.GetEntry(ManifestEntryName);
        if (entry is null)
        {
            return null;
        }

        await using var stream = entry.Open();
        return await JsonSerializer.DeserializeAsync<ZipConfigManifest>(stream, cancellationToken: cancellationToken);
    }

    private static string SafeEntrySegment(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            builder.Append(char.IsLetterOrDigit(ch) || ch is '-' or '_' or '.' ? ch : '_');
        }

        var safe = builder.ToString().Trim('.');
        return string.IsNullOrWhiteSpace(safe) ? "item" : safe;
    }

    private static async Task<MemoryStream> BufferAsync(
        Stream source,
        long limitBytes,
        string label,
        CancellationToken cancellationToken)
    {
        var buffer = new MemoryStream();
        var chunk = new byte[81920];
        long total = 0;

        while (true)
        {
            var read = await source.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken);
            if (read == 0)
            {
                break;
            }

            total += read;
            if (total > limitBytes)
            {
                buffer.Dispose();
                throw new InvalidOperationException($"{label} size exceeds {limitBytes} bytes.");
            }

            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
        }

        buffer.Position = 0;
        return buffer;
    }

    private sealed record ZipConfigManifest(
        int Version,
        IReadOnlyList<ZipMibFileManifestEntry> MibFiles);

    private sealed record ZipMibFileManifestEntry(
        string MibSetName,
        string FileName,
        string EntryName);
}
