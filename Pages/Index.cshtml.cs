using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using appsec_assignment_2.Data;
using appsec_assignment_2.Models;
using appsec_assignment_2.Services;

namespace appsec_assignment_2.Pages;

[Authorize]
[ValidateAntiForgeryToken]
public class IndexModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly EncryptionService _encryptionService;
    private readonly AuditService _auditService;
    private readonly IWebHostEnvironment _environment;
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(
        UserManager<ApplicationUser> userManager,
        EncryptionService encryptionService,
        AuditService auditService,
        IWebHostEnvironment environment,
        ApplicationDbContext dbContext,
        ILogger<IndexModel> logger)
    {
        _userManager = userManager;
        _encryptionService = encryptionService;
        _auditService = auditService;
        _environment = environment;
        _dbContext = dbContext;
        _logger = logger;
    }

    public ApplicationUser? CurrentUser { get; set; }
    public string? DecryptedNRIC { get; set; }
    public List<AuditLog> RecentActivities { get; set; } = new();
    public List<AuditLog> RecentLogins { get; set; } = new();
    public List<UserSession> ActiveSessions { get; set; } = new();
    public string? CurrentSessionId { get; set; }
    public bool TwoFactorEnabled { get; set; }

    [BindProperty]
    public IFormFile? UploadedResume { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        try
        {
            CurrentUser = await _userManager.GetUserAsync(User);

            if (CurrentUser == null)
            {
                return RedirectToPage("/Login");
            }

            CurrentSessionId = HttpContext.Session.GetString("SessionId");

            if (!string.IsNullOrEmpty(CurrentUser.EncryptedNRIC))
            {
                DecryptedNRIC = _encryptionService.TryDecrypt(CurrentUser.EncryptedNRIC);
            }

            TwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(CurrentUser);

            ActiveSessions = await _dbContext.UserSessions
                .Where(s => s.UserId == CurrentUser.Id && s.IsActive)
                .OrderByDescending(s => s.LastActivityAt)
                .ToListAsync();

            RecentActivities = await _auditService.GetUserLogsAsync(CurrentUser.Id, 10);
            RecentLogins = await _auditService.GetUserLoginLogsAsync(CurrentUser.Id, 15);

            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Index OnGet failed");
            return RedirectToPage("/Error");
        }
    }

    public static string GetDeviceDescription(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
            return "Unknown device";

        var browser = "Browser";
        if (userAgent.Contains("Edg/", StringComparison.OrdinalIgnoreCase)) browser = "Edge";
        else if (userAgent.Contains("Chrome/", StringComparison.OrdinalIgnoreCase) && !userAgent.Contains("Edg", StringComparison.OrdinalIgnoreCase)) browser = "Chrome";
        else if (userAgent.Contains("Firefox/", StringComparison.OrdinalIgnoreCase)) browser = "Firefox";
        else if (userAgent.Contains("Safari/", StringComparison.OrdinalIgnoreCase) && !userAgent.Contains("Chrome", StringComparison.OrdinalIgnoreCase)) browser = "Safari";
        else if (userAgent.Contains("OPR/", StringComparison.OrdinalIgnoreCase) || userAgent.Contains("Opera", StringComparison.OrdinalIgnoreCase)) browser = "Opera";

        var os = "Device";
        if (userAgent.Contains("Windows NT", StringComparison.OrdinalIgnoreCase)) os = "Windows";
        else if (userAgent.Contains("Mac OS", StringComparison.OrdinalIgnoreCase)) os = "macOS";
        else if (userAgent.Contains("Android", StringComparison.OrdinalIgnoreCase)) os = "Android";
        else if (userAgent.Contains("iPhone", StringComparison.OrdinalIgnoreCase) || userAgent.Contains("iPad", StringComparison.OrdinalIgnoreCase)) os = "iOS";
        else if (userAgent.Contains("Linux", StringComparison.OrdinalIgnoreCase)) os = "Linux";

        return $"{browser} on {os}";
    }

    public async Task<IActionResult> OnGetDownloadResumeAsync()
    {
        try
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null || string.IsNullOrEmpty(user.ResumePath))
            {
                return NotFound();
            }

            var fileName = Path.GetFileName(user.ResumePath);
            if (string.IsNullOrEmpty(fileName) || fileName != user.ResumePath)
            {
                return BadRequest();
            }

            var uploadsFolder = Path.Combine(_environment.ContentRootPath, "Uploads");
            var filePath = Path.Combine(uploadsFolder, fileName);
            if (!System.IO.File.Exists(filePath))
            {
                return NotFound();
            }

            var contentType = Path.GetExtension(fileName).ToLowerInvariant() switch
            {
                ".pdf" => "application/pdf",
                ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                _ => "application/octet-stream"
            };

            return PhysicalFile(filePath, contentType, fileName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Index OnGetDownloadResume failed");
            return NotFound();
        }
    }

    public async Task<IActionResult> OnPostUploadResumeAsync()
    {
        try
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            if (UploadedResume == null || UploadedResume.Length == 0)
            {
                ModelState.AddModelError(string.Empty, "Please select a file to upload.");
                await LoadPageDataAsync(user);
                return Page();
            }

            var validation = ValidateResumeFile(UploadedResume);
            if (!validation.IsValid)
            {
                ModelState.AddModelError(string.Empty, validation.ErrorMessage!);
                await LoadPageDataAsync(user);
                return Page();
            }

            var uploadsFolder = Path.Combine(_environment.ContentRootPath, "Uploads");
            Directory.CreateDirectory(uploadsFolder);

            if (!string.IsNullOrEmpty(user.ResumePath))
            {
                var oldPath = Path.Combine(uploadsFolder, Path.GetFileName(user.ResumePath));
                if (System.IO.File.Exists(oldPath))
                {
                    System.IO.File.Delete(oldPath);
                }
            }

            var uniqueFileName = $"{Guid.NewGuid()}{Path.GetExtension(UploadedResume.FileName)}";
            var filePath = Path.Combine(uploadsFolder, uniqueFileName);
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await UploadedResume.CopyToAsync(stream);
            }

            var hadResume = !string.IsNullOrEmpty(user.ResumePath);
            user.ResumePath = uniqueFileName;
            user.UpdatedAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            await _auditService.LogAsync(user.Id, "ResumeUpdated", hadResume ? "Resume replaced" : "Resume uploaded", HttpContext);

            TempData["ResumeUploadSuccess"] = hadResume ? "Resume updated successfully." : "Resume uploaded successfully.";
            return RedirectToPage("/Index");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Index OnPostUploadResume failed");
            ModelState.AddModelError(string.Empty, "An error occurred. Please try again.");
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                await LoadPageDataAsync(user);
            }
            return Page();
        }
    }

    private async Task LoadPageDataAsync(ApplicationUser user)
    {
        CurrentUser = user;
        CurrentSessionId = HttpContext.Session.GetString("SessionId");
        if (!string.IsNullOrEmpty(user.EncryptedNRIC))
        {
            DecryptedNRIC = _encryptionService.TryDecrypt(user.EncryptedNRIC);
        }
        TwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
        ActiveSessions = await _dbContext.UserSessions
            .Where(s => s.UserId == user.Id && s.IsActive)
            .OrderByDescending(s => s.LastActivityAt)
            .ToListAsync();
        RecentActivities = await _auditService.GetUserLogsAsync(user.Id, 10);
        RecentLogins = await _auditService.GetUserLoginLogsAsync(user.Id, 15);
    }

    private static readonly string[] AllowedResumeMimeTypes =
    {
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    };

    private static (bool IsValid, string? ErrorMessage) ValidateResumeFile(IFormFile file)
    {
        if (file.Length > 5 * 1024 * 1024)
        {
            return (false, "Resume file size cannot exceed 5MB.");
        }

        var contentType = (file.ContentType ?? string.Empty).Split(';')[0].Trim();
        if (string.IsNullOrEmpty(contentType) || !AllowedResumeMimeTypes.Contains(contentType, StringComparer.OrdinalIgnoreCase))
        {
            return (false, "Invalid file type. Only PDF and DOCX are allowed.");
        }

        var allowedExtensions = new[] { ".pdf", ".docx" };
        var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (!allowedExtensions.Contains(extension))
        {
            return (false, "Only PDF and DOCX files are allowed.");
        }

        using var reader = new BinaryReader(file.OpenReadStream());
        var headerBytes = reader.ReadBytes(8);

        bool isValidPdf = headerBytes.Length >= 5 &&
            headerBytes[0] == 0x25 && headerBytes[1] == 0x50 &&
            headerBytes[2] == 0x44 && headerBytes[3] == 0x46 &&
            headerBytes[4] == 0x2D;

        bool isValidDocx = headerBytes.Length >= 4 &&
            headerBytes[0] == 0x50 && headerBytes[1] == 0x4B &&
            headerBytes[2] == 0x03 && headerBytes[3] == 0x04;

        if (extension == ".pdf" && !isValidPdf)
        {
            return (false, "Invalid PDF file.");
        }

        if (extension == ".docx" && !isValidDocx)
        {
            return (false, "Invalid DOCX file.");
        }

        return (true, null);
    }
}
