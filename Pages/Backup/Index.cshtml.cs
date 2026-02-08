using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using appsec_assignment_2.Services;

namespace appsec_assignment_2.Pages.Backup;

[Authorize]
[ValidateAntiForgeryToken]
public class IndexModel : PageModel
{
    private readonly DatabaseBackupService _backupService;
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(DatabaseBackupService backupService, ILogger<IndexModel> logger)
    {
        _backupService = backupService;
        _logger = logger;
    }

    public IReadOnlyList<BackupEntry> Backups { get; set; } = Array.Empty<BackupEntry>();
    public string? Message { get; set; }
    public bool? BackupSuccess { get; set; }

    public void OnGet(string? message, bool? success)
    {
        Backups = _backupService.ListBackups();
        Message = message;
        BackupSuccess = success;
    }

    public async Task<IActionResult> OnPostRunBackupAsync()
    {
        var (success, errorMessage) = await _backupService.CreateBackupAsync();
        _logger.LogInformation("Manual backup triggered by user {User}: {Result}", User.Identity?.Name, success ? "success" : "failed");
        var message = success ? "Backup created successfully." : ("Backup failed. " + (errorMessage ?? ""));
        return RedirectToPage(new { message, success });
    }

    public IActionResult OnGetDownload(string? file)
    {
        if (string.IsNullOrEmpty(file))
            return NotFound();

        var decrypted = _backupService.DecryptBackupByFileName(file);
        if (decrypted == null)
            return NotFound();

        var downloadName = Path.GetFileNameWithoutExtension(file);
        if (!downloadName.StartsWith("backup_", StringComparison.Ordinal))
            downloadName = "backup_" + downloadName;
        downloadName += ".db";

        return File(decrypted, "application/octet-stream", downloadName);
    }
}
