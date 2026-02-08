using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using appsec_assignment_2.Data;
using appsec_assignment_2.Models;
using appsec_assignment_2.Services;
using appsec_assignment_2.ViewModels;

namespace appsec_assignment_2.Pages;

[Authorize]
[ValidateAntiForgeryToken]
public class ChangePasswordModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly AuditService _auditService;
    private readonly ApplicationDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly ILogger<ChangePasswordModel> _logger;

    public ChangePasswordModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        AuditService auditService,
        ApplicationDbContext context,
        IConfiguration configuration,
        ILogger<ChangePasswordModel> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _auditService = auditService;
        _context = context;
        _configuration = configuration;
        _logger = logger;
    }

    [BindProperty]
    public ChangePasswordViewModel Input { get; set; } = new();

    public bool MustChangePassword { get; set; }

    public string? MinAgeMessage { get; set; }

    public IActionResult OnGet(bool mustChange = false)
    {
        try
        {
            MustChangePassword = mustChange;
            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ChangePassword OnGet failed");
            return RedirectToPage("/Error");
        }
    }

    public async Task<IActionResult> OnPostAsync()
    {
        try
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            var minAgeMinutes = _configuration.GetValue<int>("PasswordPolicy:MinimumAgeMinutes", 1);
            if (user.LastPasswordChangeDate.HasValue)
            {
                var timeSinceChange = DateTime.UtcNow - user.LastPasswordChangeDate.Value;
                if (timeSinceChange.TotalMinutes < minAgeMinutes)
                {
                    var remainingMinutes = minAgeMinutes - (int)timeSinceChange.TotalMinutes;
                    ModelState.AddModelError(string.Empty,
                        $"Cannot change password yet. Please wait {remainingMinutes} more minute(s).");
                    return Page();
                }
            }

            var result = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);

            if (result.Succeeded)
            {
                var passwordHistory = new PasswordHistory
                {
                    UserId = user.Id,
                    PasswordHash = user.PasswordHash!,
                    CreatedAt = DateTime.UtcNow
                };
                _context.PasswordHistories.Add(passwordHistory);

                user.LastPasswordChangeDate = DateTime.UtcNow;
                user.MustChangePassword = false;
                user.UpdatedAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
                await _context.SaveChangesAsync();

                await _auditService.LogAsync(user.Id, "PasswordChanged", "Password changed successfully", HttpContext);

                await _signInManager.RefreshSignInAsync(user);

                TempData["SuccessMessage"] = "Your password has been changed successfully.";
                return RedirectToPage("/Index");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ChangePassword OnPost failed");
            ModelState.AddModelError(string.Empty, "An error occurred. Please try again.");
            return Page();
        }
    }
}
