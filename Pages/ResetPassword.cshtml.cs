using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using appsec_assignment_2.Data;
using appsec_assignment_2.Models;
using appsec_assignment_2.Services;

namespace appsec_assignment_2.Pages;

[ValidateAntiForgeryToken]
public class ResetPasswordModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuditService _auditService;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<ResetPasswordModel> _logger;

    public ResetPasswordModel(
        UserManager<ApplicationUser> userManager,
        AuditService auditService,
        ApplicationDbContext context,
        ILogger<ResetPasswordModel> logger)
    {
        _userManager = userManager;
        _auditService = auditService;
        _context = context;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool ResetSuccessful { get; set; }

    public class InputModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        [StringLength(256)]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Invalid or expired reset link")]
        [StringLength(500, MinimumLength = 1)]
        public string Token { get; set; } = string.Empty;

        [Required(ErrorMessage = "New password is required")]
        [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z\d]).{12,}$",
            ErrorMessage = "Password must contain at least one lowercase, one uppercase, one digit, and one special character")]
        [DataType(DataType.Password)]
        [Display(Name = "New Password")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please confirm your password")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public IActionResult OnGet(string? token, string? email)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(email))
                return RedirectToPage("/Login");

            if (token.Length > 500 || email.Length > 256)
                return RedirectToPage("/Login");

            if (!email.Contains('@') || email.IndexOf('@') < 1 || email.IndexOf('@') > email.Length - 2)
                return RedirectToPage("/Login");

            Input.Token = token.Trim();
            Input.Email = email.Trim();
            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ResetPassword OnGet failed");
            return RedirectToPage("/Login");
        }
    }

    public async Task<IActionResult> OnPostAsync()
    {
        try
        {
            if (!ModelState.IsValid)
                return Page();

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                ResetSuccessful = true;
                return Page();
            }

            var result = await _userManager.ResetPasswordAsync(user, Input.Token, Input.Password);

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

                await _auditService.LogAsync(user.Id, "PasswordReset", "Password reset via email link", HttpContext);

                ResetSuccessful = true;
                return Page();
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ResetPassword OnPost failed");
            ModelState.AddModelError(string.Empty, "An error occurred. Please try again.");
            return Page();
        }
    }
}
