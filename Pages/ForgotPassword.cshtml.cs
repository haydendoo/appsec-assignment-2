using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using appsec_assignment_2.Models;
using appsec_assignment_2.Services;

namespace appsec_assignment_2.Pages;

public class ForgotPasswordModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuditService _auditService;
    private readonly IEmailSender _emailSender;
    private readonly ILogger<ForgotPasswordModel> _logger;

    public ForgotPasswordModel(
        UserManager<ApplicationUser> userManager,
        AuditService auditService,
        IEmailSender emailSender,
        ILogger<ForgotPasswordModel> logger)
    {
        _userManager = userManager;
        _auditService = auditService;
        _emailSender = emailSender;
        _logger = logger;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public bool EmailSent { get; set; }

    public class InputModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; } = string.Empty;
    }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await _userManager.FindByEmailAsync(Input.Email);
        
        if (user != null)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = Url.Page(
                "/ResetPassword",
                pageHandler: null,
                values: new { token, email = Input.Email },
                protocol: Request.Scheme);

            var subject = "Reset your password";
            var body = $"""
                <p>You requested a password reset. Click the link below to reset your password:</p>
                <p><a href="{callbackUrl}">Reset password</a></p>
                <p>If you did not request this, you can ignore this email.</p>
                <p>This link will expire in 1 hour.</p>
                """;
            await _emailSender.SendEmailAsync(Input.Email, subject, body);

            await _auditService.LogAsync(user.Id, "PasswordResetRequested", "Password reset link generated", HttpContext);
        }

        // Always show success to prevent email enumeration
        EmailSent = true;
        return Page();
    }
}
