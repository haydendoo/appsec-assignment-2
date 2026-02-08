using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using appsec_assignment_2.Data;
using appsec_assignment_2.Models;
using appsec_assignment_2.Services;

namespace appsec_assignment_2.Pages;

[ValidateAntiForgeryToken]
public class TwoFactorVerifyModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuditService _auditService;
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<TwoFactorVerifyModel> _logger;

    public TwoFactorVerifyModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        AuditService auditService,
        ApplicationDbContext dbContext,
        ILogger<TwoFactorVerifyModel> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditService = auditService;
        _dbContext = dbContext;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ReturnUrl { get; set; }
    public bool RememberMe { get; set; }

    public class InputModel
    {
        [Required(ErrorMessage = "Verification code is required")]
        [StringLength(8, MinimumLength = 6, ErrorMessage = "Invalid code length")]
        [RegularExpression(@"^[\d\s\-]+$", ErrorMessage = "Code can only contain digits, spaces, or hyphens")]
        [Display(Name = "Verification Code")]
        public string TwoFactorCode { get; set; } = string.Empty;

        [Display(Name = "Remember this device")]
        public bool RememberMachine { get; set; }
    }

    public async Task<IActionResult> OnGetAsync(string? returnUrl = null, bool rememberMe = false)
    {
        try
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            ReturnUrl = returnUrl ?? Url.Content("~/");
            RememberMe = rememberMe;

            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TwoFactorVerify OnGet failed");
            return RedirectToPage("/Login");
        }
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null, bool rememberMe = false)
    {
        returnUrl ??= Url.Content("~/");
        ReturnUrl = returnUrl;
        RememberMe = rememberMe;

        try
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            var authenticatorCode = Input.TwoFactorCode.Replace(" ", "").Replace("-", "");
            if (authenticatorCode.Length != 6 || !authenticatorCode.All(char.IsDigit))
            {
                ModelState.AddModelError(string.Empty, "Invalid authenticator code format.");
                return Page();
            }

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(
                authenticatorCode,
                rememberMe,
                Input.RememberMachine);

            if (result.Succeeded)
            {
                var authToken = Guid.NewGuid().ToString();
                var sessionId = Guid.NewGuid().ToString();

                HttpContext.Session.SetString("AuthToken", authToken);
                HttpContext.Session.SetString("SessionId", sessionId);

                Response.Cookies.Append("AuthToken", authToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = rememberMe ? DateTimeOffset.UtcNow.AddDays(30) : null
                });

                var userSession = new UserSession
                {
                    UserId = user.Id,
                    SessionId = sessionId,
                    AuthToken = authToken,
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                    UserAgent = HttpContext.Request.Headers.UserAgent.ToString(),
                    CreatedAt = DateTime.UtcNow,
                    LastActivityAt = DateTime.UtcNow,
                    IsActive = true
                };
                _dbContext.UserSessions.Add(userSession);
                await _dbContext.SaveChangesAsync();

                user.CurrentSessionId = sessionId;
                user.UpdatedAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                await _auditService.LogAsync(user.Id, "2FAVerified", "Two-factor authentication verified", HttpContext);

                return LocalRedirect(returnUrl);
            }

            if (result.IsLockedOut)
            {
                await _auditService.LogAsync(user.Id, "AccountLocked", "Account locked after failed 2FA attempts", HttpContext);
                return RedirectToPage("/Login");
            }

            await _auditService.LogAsync(user.Id, "2FAFailed", "Invalid 2FA code entered", HttpContext);
            ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TwoFactorVerify OnPost failed");
            ModelState.AddModelError(string.Empty, "An error occurred. Please try again.");
            return Page();
        }
    }
}
