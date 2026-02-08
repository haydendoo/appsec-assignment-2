using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using appsec_assignment_2.Data;
using appsec_assignment_2.Models;
using appsec_assignment_2.Services;
using appsec_assignment_2.ViewModels;

namespace appsec_assignment_2.Pages;

[ValidateAntiForgeryToken]
public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuditService _auditService;
    private readonly RecaptchaService _recaptchaService;
    private readonly IConfiguration _configuration;
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<LoginModel> _logger;

    public LoginModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        AuditService auditService,
        RecaptchaService recaptchaService,
        IConfiguration configuration,
        ApplicationDbContext dbContext,
        ILogger<LoginModel> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditService = auditService;
        _recaptchaService = recaptchaService;
        _configuration = configuration;
        _dbContext = dbContext;
        _logger = logger;
    }

    [BindProperty]
    public LoginViewModel Input { get; set; } = new();

    public string? RecaptchaSiteKey => _configuration["Recaptcha:SiteKey"];

    public string? ReturnUrl { get; set; }

    [TempData]
    public string? SuccessMessage { get; set; }

    public string? LockoutMessage { get; set; }

    public IActionResult OnGet(string? returnUrl = null)
    {
        try
        {
            ReturnUrl = returnUrl ?? Url.Content("~/");
            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login OnGet failed");
            return RedirectToPage("/Error");
        }
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");

        try
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

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
            user = await _userManager.FindByEmailAsync(Input.Email);
            if (user != null)
            {
                // Generate AuthToken GUID for session fixation protection
                var authToken = Guid.NewGuid().ToString();
                var sessionId = Guid.NewGuid().ToString();
                
                // Store AuthToken in server-side session
                HttpContext.Session.SetString("AuthToken", authToken);
                HttpContext.Session.SetString("SessionId", sessionId);
                
                // Store AuthToken in cookie (HttpOnly, Secure)
                Response.Cookies.Append("AuthToken", authToken, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = Input.RememberMe ? DateTimeOffset.UtcNow.AddDays(30) : null
                });

                // Create session record in database for multi-session tracking
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

                await _auditService.LogAsync(user.Id, "LoginSuccess", "User logged in successfully", HttpContext);

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
            // Do not log the provided email address to avoid exposing potentially private information
            await _auditService.LogAsync(null, "LoginFailed", "Unknown user login attempt", HttpContext);
        }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login OnPost failed");
            ModelState.AddModelError(string.Empty, "An error occurred. Please try again.");
            return Page();
        }
    }
}
