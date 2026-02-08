using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QRCoder;
using appsec_assignment_2.Models;
using appsec_assignment_2.Services;

namespace appsec_assignment_2.Pages;

[Authorize]
[ValidateAntiForgeryToken]
public class TwoFactorSetupModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuditService _auditService;
    private readonly UrlEncoder _urlEncoder;
    private readonly ILogger<TwoFactorSetupModel> _logger;

    public TwoFactorSetupModel(
        UserManager<ApplicationUser> userManager,
        AuditService auditService,
        UrlEncoder urlEncoder,
        ILogger<TwoFactorSetupModel> logger)
    {
        _userManager = userManager;
        _auditService = auditService;
        _urlEncoder = urlEncoder;
        _logger = logger;
    }

    public string? SharedKey { get; set; }
    public string? QrCodeDataUri { get; set; }
    public bool Is2FAEnabled { get; set; }

    [BindProperty]
    [Required(ErrorMessage = "Verification code is required")]
    [StringLength(8, MinimumLength = 6, ErrorMessage = "Code must be 6 digits")]
    [RegularExpression(@"^[\d\s\-]+$", ErrorMessage = "Code can only contain digits, spaces, or hyphens")]
    public string VerificationCode { get; set; } = string.Empty;

    [TempData]
    public string? StatusMessage { get; set; }

    public async Task<IActionResult> OnGetAsync()
    {
        try
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            Is2FAEnabled = await _userManager.GetTwoFactorEnabledAsync(user);

            if (!Is2FAEnabled)
            {
                await LoadSharedKeyAndQrCodeAsync(user);
            }

            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TwoFactorSetup OnGet failed");
            return RedirectToPage("/Error");
        }
    }

    public async Task<IActionResult> OnPostEnableAsync()
    {
        try
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            if (!ModelState.IsValid)
            {
                await LoadSharedKeyAndQrCodeAsync(user);
                return Page();
            }

            var verificationCode = VerificationCode.Replace(" ", "").Replace("-", "");
            if (verificationCode.Length != 6 || !verificationCode.All(char.IsDigit))
            {
                ModelState.AddModelError("VerificationCode", "Invalid verification code.");
                await LoadSharedKeyAndQrCodeAsync(user);
                return Page();
            }

            var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider,
                verificationCode);

            if (!is2faTokenValid)
            {
                ModelState.AddModelError("VerificationCode", "Invalid verification code.");
                await LoadSharedKeyAndQrCodeAsync(user);
                return Page();
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            await _auditService.LogAsync(user.Id, "2FAEnabled", "Two-factor authentication enabled", HttpContext);

            StatusMessage = "Two-factor authentication has been enabled successfully.";
            return RedirectToPage();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TwoFactorSetup OnPostEnable failed");
            ModelState.AddModelError(string.Empty, "An error occurred. Please try again.");
            return Page();
        }
    }

    public async Task<IActionResult> OnPostDisableAsync()
    {
        try
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            await _userManager.SetTwoFactorEnabledAsync(user, false);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _auditService.LogAsync(user.Id, "2FADisabled", "Two-factor authentication disabled", HttpContext);

            StatusMessage = "Two-factor authentication has been disabled.";
            return RedirectToPage();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TwoFactorSetup OnPostDisable failed");
            ModelState.AddModelError(string.Empty, "An error occurred. Please try again.");
            return Page();
        }
    }

    private async Task LoadSharedKeyAndQrCodeAsync(ApplicationUser user)
    {
        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        SharedKey = FormatKey(key!);

        var email = await _userManager.GetEmailAsync(user);
        var authenticatorUri = GenerateQrCodeUri(email!, key!);

        // Generate QR code
        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(authenticatorUri, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new PngByteQRCode(qrCodeData);
        var qrCodeBytes = qrCode.GetGraphic(5);
        QrCodeDataUri = $"data:image/png;base64,{Convert.ToBase64String(qrCodeBytes)}";
    }

    private static string FormatKey(string key)
    {
        var result = new StringBuilder();
        var pos = 0;
        while (pos < key.Length)
        {
            if (pos > 0)
            {
                result.Append(' ');
            }
            result.Append(key.AsSpan(pos, Math.Min(4, key.Length - pos)));
            pos += 4;
        }
        return result.ToString().ToLowerInvariant();
    }

    private string GenerateQrCodeUri(string email, string key)
    {
        const string authenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
        return string.Format(
            authenticatorUriFormat,
            _urlEncoder.Encode("AceJobAgency"),
            _urlEncoder.Encode(email),
            key);
    }
}
