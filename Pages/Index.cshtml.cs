using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using appsec_assignment_2.Models;
using appsec_assignment_2.Services;

namespace appsec_assignment_2.Pages;

[Authorize]
public class IndexModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly EncryptionService _encryptionService;
    private readonly AuditService _auditService;

    public IndexModel(
        UserManager<ApplicationUser> userManager,
        EncryptionService encryptionService,
        AuditService auditService)
    {
        _userManager = userManager;
        _encryptionService = encryptionService;
        _auditService = auditService;
    }

    public ApplicationUser? CurrentUser { get; set; }
    public string? DecryptedNRIC { get; set; }
    public List<AuditLog> RecentActivities { get; set; } = new();
    public bool TwoFactorEnabled { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        CurrentUser = await _userManager.GetUserAsync(User);
        
        if (CurrentUser == null)
        {
            return RedirectToPage("/Login");
        }

        // Validate session (single session enforcement)
        var storedSessionId = HttpContext.Session.GetString("SessionId");
        if (storedSessionId != CurrentUser.CurrentSessionId)
        {
            HttpContext.Session.Clear();
            await _userManager.UpdateSecurityStampAsync(CurrentUser);
            return RedirectToPage("/Login");
        }

        // Decrypt NRIC for display
        if (!string.IsNullOrEmpty(CurrentUser.EncryptedNRIC))
        {
            DecryptedNRIC = _encryptionService.Decrypt(CurrentUser.EncryptedNRIC);
        }

        // Get 2FA status
        TwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(CurrentUser);

        // Get recent audit logs
        RecentActivities = await _auditService.GetUserLogsAsync(CurrentUser.Id, 10);

        return Page();
    }
}
