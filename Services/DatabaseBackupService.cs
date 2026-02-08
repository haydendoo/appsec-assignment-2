using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;

namespace appsec_assignment_2.Services;

public class DatabaseBackupService
{
    private readonly BackupOptions _options;
    private readonly IConfiguration _configuration;
    private readonly IHostEnvironment _environment;
    private readonly EncryptionService _encryption;
    private readonly ILogger<DatabaseBackupService> _logger;

    public DatabaseBackupService(
        IOptions<BackupOptions> options,
        IConfiguration configuration,
        IHostEnvironment environment,
        EncryptionService encryption,
        ILogger<DatabaseBackupService> logger)
    {
        _options = options.Value;
        _configuration = configuration;
        _environment = environment;
        _encryption = encryption;
        _logger = logger;
    }

    public async Task<(bool Success, string? ErrorMessage)> CreateBackupAsync(CancellationToken cancellationToken = default)
    {
        var connectionString = _options.ConnectionString
            ?? _configuration.GetConnectionString("DefaultConnection");
        if (string.IsNullOrEmpty(connectionString))
        {
            _logger.LogWarning("Backup skipped: ConnectionString not configured");
            return (false, "Connection string not configured.");
        }

        var dbPath = ResolveDatabasePath(connectionString);
        if (!File.Exists(dbPath))
        {
            _logger.LogWarning("Backup skipped: Database file not found at {Path}", dbPath);
            return (false, $"Database file not found at {dbPath}");
        }

        var backupDir = ResolveBackupDirectory();
        Directory.CreateDirectory(backupDir);

        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        var randomSuffix = Convert.ToBase64String(RandomNumberGenerator.GetBytes(6)).Replace("+", "").Replace("/", "").Replace("=", "");
        var backupFileName = $"backup_{timestamp}.enc";
        var backupPath = Path.Combine(backupDir, backupFileName);
        var tempPath = Path.Combine(Path.GetTempPath(), $"sqlite_backup_{timestamp}_{randomSuffix}_{Guid.NewGuid():N}.tmp");

        try
        {
            byte[] dbBytes = await CreateBackupViaSqliteApiAsync(connectionString, dbPath, tempPath, cancellationToken);

            var encrypted = _encryption.EncryptBytes(dbBytes);
            await File.WriteAllBytesAsync(backupPath, encrypted, cancellationToken);

            _logger.LogInformation("Backup created: {Path}", backupPath);

            await ApplyRetentionAsync(backupDir, cancellationToken);
            return (true, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Backup failed");
            if (File.Exists(backupPath))
                File.Delete(backupPath);
            return (false, ex.Message);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { /* ignore */ }
            }
        }
    }

    public byte[]? DecryptBackup(string backupFilePath)
    {
        if (!File.Exists(backupFilePath))
            return null;

        try
        {
            var payload = File.ReadAllBytes(backupFilePath);
            return _encryption.DecryptBytes(payload);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to decrypt backup {Path}", backupFilePath);
            return null;
        }
    }

    public IReadOnlyList<BackupEntry> ListBackups()
    {
        var backupDir = ResolveBackupDirectory();
        if (!Directory.Exists(backupDir))
            return Array.Empty<BackupEntry>();

        return Directory.GetFiles(backupDir, "backup_*.enc")
            .Select(f => new FileInfo(f))
            .Where(fi => IsSafeBackupFileName(fi.Name))
            .OrderByDescending(fi => fi.CreationTimeUtc)
            .Select(fi => new BackupEntry(fi.Name, fi.CreationTimeUtc))
            .ToList();
    }

    public byte[]? DecryptBackupByFileName(string fileName)
    {
        if (!IsSafeBackupFileName(fileName))
            return null;

        var backupDir = ResolveBackupDirectory();
        var fullPath = Path.GetFullPath(Path.Combine(backupDir, fileName));
        if (!fullPath.StartsWith(Path.GetFullPath(backupDir), StringComparison.OrdinalIgnoreCase))
            return null;

        return DecryptBackup(fullPath);
    }

    private static bool IsSafeBackupFileName(string fileName)
    {
        if (string.IsNullOrEmpty(fileName) || fileName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            return false;
        return fileName.StartsWith("backup_", StringComparison.Ordinal) && fileName.EndsWith(".enc", StringComparison.OrdinalIgnoreCase);
    }

    private async Task<byte[]> CreateBackupViaSqliteApiAsync(string connectionString, string dbPath, string tempPath, CancellationToken cancellationToken)
    {
        var sourceCs = new SqliteConnectionStringBuilder(connectionString) { DataSource = dbPath }.ToString();
        var destCs = new SqliteConnectionStringBuilder { DataSource = tempPath, Pooling = false }.ToString();

        await using (var source = new SqliteConnection(sourceCs))
        await using (var dest = new SqliteConnection(destCs))
        {
            await source.OpenAsync(cancellationToken);
            await dest.OpenAsync(cancellationToken);
            source.BackupDatabase(dest);
        }

        return await File.ReadAllBytesAsync(tempPath, cancellationToken);
    }

    private string ResolveDatabasePath(string connectionString)
    {
        var builder = new SqliteConnectionStringBuilder(connectionString);
        var dataSource = builder.DataSource;
        if (Path.IsPathRooted(dataSource))
            return dataSource;
        return Path.Combine(_environment.ContentRootPath ?? AppContext.BaseDirectory, dataSource);
    }

    private string ResolveBackupDirectory()
    {
        var path = _options.Directory;
        if (string.IsNullOrEmpty(path))
            path = Path.Combine(_environment.ContentRootPath ?? AppContext.BaseDirectory, "Backups");
        if (!Path.IsPathRooted(path))
            path = Path.Combine(_environment.ContentRootPath ?? AppContext.BaseDirectory, path);
        return Path.GetFullPath(path);
    }

    private async Task ApplyRetentionAsync(string backupDir, CancellationToken cancellationToken)
    {
        var retention = _options.RetentionCount;
        if (retention <= 0)
            return;

        var files = Directory.GetFiles(backupDir, "backup_*.enc")
            .Select(f => new FileInfo(f))
            .OrderByDescending(fi => fi.CreationTimeUtc)
            .ToList();

        foreach (var file in files.Skip(retention))
        {
            try
            {
                file.Delete();
                _logger.LogInformation("Retention: removed old backup {Path}", file.FullName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not delete old backup {Path}", file.FullName);
            }
        }

        await Task.CompletedTask;
    }
}

public record BackupEntry(string FileName, DateTime CreatedUtc);

public class BackupOptions
{
    public const string SectionName = "Backup";

    public string? ConnectionString { get; set; }
    public string? Directory { get; set; }
    public int RetentionCount { get; set; } = 7;
    public int IntervalMinutes { get; set; }
}
