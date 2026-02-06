using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using appsec_assignment_2.Models;
using appsec_assignment_2.Services;
using appsec_assignment_2.ViewModels;

namespace appsec_assignment_2.Pages;

public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuditService _auditService;
    private readonly RecaptchaService _recaptchaService;
    private readonly IConfiguration _configuration;

    public LoginModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        AuditService auditService,
        RecaptchaService recaptchaService,
        IConfiguration configuration)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditService = auditService;
        _recaptchaService = recaptchaService;
        _configuration = configuration;
    }

    [BindProperty]
    public LoginViewModel Input { get; set; } = new();

    public string? RecaptchaSiteKey => _configuration["Recaptcha:SiteKey"];

    public string? ReturnUrl { get; set; }

    [TempData]
    public string? SuccessMessage { get; set; }

    public string? LockoutMessage { get; set; }

    public void OnGet(string? returnUrl = null)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");

        if (!ModelState.IsValid)
        {
            return Page();
        }

        // Verify reCAPTCHA
        if (!string.IsNullOrEmpty(RecaptchaSiteKey))
        {
            var recaptchaResult = await _recaptchaService.VerifyAsync(Input.RecaptchaToken ?? string.Empty);
            if (!recaptchaResult.Success || recaptchaResult.Score < 0.5)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return Page();
            }
        }

        var user = await _userManager.FindByEmailAsync(Input.Email);

        if (user != null)
        {
            // Check if account is locked out
            if (await _userManager.IsLockedOutAsync(user))
            {
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                var remainingTime = lockoutEnd.HasValue ? lockoutEnd.Value - DateTimeOffset.UtcNow : TimeSpan.Zero;
                
                await _auditService.LogAsync(user.Id, "LoginFailed", "Account locked out", HttpContext);
                
                LockoutMessage = $"Account locked. Try again in {Math.Ceiling(remainingTime.TotalMinutes)} minutes.";
                ModelState.AddModelError(string.Empty, LockoutMessage);
                return Page();
            }

            // Check password age (force change if expired)
            var maxAgeDays = _configuration.GetValue<int>("PasswordPolicy:MaximumAgeDays", 90);
            if (user.LastPasswordChangeDate.HasValue)
            {
                var passwordAge = DateTime.UtcNow - user.LastPasswordChangeDate.Value;
                if (passwordAge.TotalDays > maxAgeDays)
                {
                    user.MustChangePassword = true;
                    await _userManager.UpdateAsync(user);
                }
            }
        }

        var result = await _signInManager.PasswordSignInAsync(
            Input.Email,
            Input.Password,
            Input.RememberMe,
            lockoutOnFailure: true);

        if (result.Succeeded)
        {
            // Update session ID for single session enforcement
            user = await _userManager.FindByEmailAsync(Input.Email);
            if (user != null)
            {
                user.CurrentSessionId = Guid.NewGuid().ToString();
                user.UpdatedAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                // Store session ID in session
                HttpContext.Session.SetString("SessionId", user.CurrentSessionId);

                await _auditService.LogAsync(user.Id, "LoginSuccess", "User logged in successfully", HttpContext);

                // Check if must change password
                if (user.MustChangePassword)
                {
                    return RedirectToPage("/ChangePassword", new { mustChange = true });
                }
            }

            return LocalRedirect(returnUrl);
        }

        if (result.RequiresTwoFactor)
        {
            return RedirectToPage("/TwoFactorVerify", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
        }

        if (result.IsLockedOut)
        {
            if (user != null)
            {
                await _auditService.LogAsync(user.Id, "AccountLocked", "Account locked after failed attempts", HttpContext);
            }
            
            LockoutMessage = "Account locked due to multiple failed login attempts. Please try again later.";
            ModelState.AddModelError(string.Empty, LockoutMessage);
            return Page();
        }

        // Log failed attempt
        if (user != null)
        {
            await _auditService.LogAsync(user.Id, "LoginFailed", "Invalid password", HttpContext);
        }
        else
        {
            await _auditService.LogAsync(null, "LoginFailed", $"Unknown user: {Input.Email}", HttpContext);
        }

        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return Page();
    }
}
