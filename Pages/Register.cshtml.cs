using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text;
using appsec_assignment_2.Data;
using appsec_assignment_2.Models;
using appsec_assignment_2.Services;
using appsec_assignment_2.ViewModels;

namespace appsec_assignment_2.Pages;

[ValidateAntiForgeryToken]
public class RegisterModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly EncryptionService _encryptionService;
    private readonly AuditService _auditService;
    private readonly RecaptchaService _recaptchaService;
    private readonly IWebHostEnvironment _environment;
    private readonly IConfiguration _configuration;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<RegisterModel> _logger;

    public RegisterModel(
        UserManager<ApplicationUser> userManager,
        EncryptionService encryptionService,
        AuditService auditService,
        RecaptchaService recaptchaService,
        IWebHostEnvironment environment,
        IConfiguration configuration,
        ApplicationDbContext context,
        ILogger<RegisterModel> logger)
    {
        _userManager = userManager;
        _encryptionService = encryptionService;
        _auditService = auditService;
        _recaptchaService = recaptchaService;
        _environment = environment;
        _configuration = configuration;
        _context = context;
        _logger = logger;
    }

    [BindProperty]
    public RegisterViewModel Input { get; set; } = new();

    public string? RecaptchaSiteKey => _configuration["Recaptcha:SiteKey"];

    public IActionResult OnGet()
    {
        try
        {
            Input.DateOfBirth = DateTime.Today;
            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Register OnGet failed");
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

            if (!string.IsNullOrEmpty(RecaptchaSiteKey))
        {
            var recaptchaResult = await _recaptchaService.VerifyAsync(Input.RecaptchaToken ?? string.Empty);
            if (!recaptchaResult.Success || recaptchaResult.Score < 0.5)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return Page();
            }
        }

        // Check for duplicate email
        var existingUser = await _userManager.FindByEmailAsync(Input.Email);
        if (existingUser != null)
        {
            ModelState.AddModelError("Input.Email", "An account with this email already exists.");
            return Page();
        }

        // Handle resume upload
        string? resumePath = null;
        if (Input.Resume != null)
        {
            var validationResult = ValidateResumeFile(Input.Resume);
            if (!validationResult.IsValid)
            {
                ModelState.AddModelError("Input.Resume", validationResult.ErrorMessage!);
                return Page();
            }

            resumePath = await SaveResumeAsync(Input.Resume);
        }

        // Create user
        var user = new ApplicationUser
        {
            UserName = Input.Email,
            Email = Input.Email,
            FirstName = Input.FirstName,
            LastName = Input.LastName,
            Gender = Input.Gender,
            EncryptedNRIC = _encryptionService.Encrypt(Input.NRIC),
            DateOfBirth = Input.DateOfBirth,
            ResumePath = resumePath,
            WhoAmI = Input.WhoAmI,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            LastPasswordChangeDate = DateTime.UtcNow
        };

        var result = await _userManager.CreateAsync(user, Input.Password);

        if (result.Succeeded)
        {
            // Save password to history
            var passwordHistory = new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash!,
                CreatedAt = DateTime.UtcNow
            };
            _context.PasswordHistories.Add(passwordHistory);
            await _context.SaveChangesAsync();

            await _auditService.LogAsync(user.Id, "Registration", "User registered successfully", HttpContext);
            
            TempData["SuccessMessage"] = "Registration successful! Please log in.";
            return RedirectToPage("/Login");
        }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Register OnPost failed");
            ModelState.AddModelError(string.Empty, "An error occurred. Please try again.");
            return Page();
        }
    }

    private static readonly string[] AllowedResumeMimeTypes =
    {
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    };

    private (bool IsValid, string? ErrorMessage) ValidateResumeFile(IFormFile file)
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

        // Check magic bytes
        using var reader = new BinaryReader(file.OpenReadStream());
        var headerBytes = reader.ReadBytes(8);

        bool isValidPdf = headerBytes.Length >= 5 && 
            headerBytes[0] == 0x25 && headerBytes[1] == 0x50 && 
            headerBytes[2] == 0x44 && headerBytes[3] == 0x46 &&
            headerBytes[4] == 0x2D; // %PDF-

        bool isValidDocx = headerBytes.Length >= 4 && 
            headerBytes[0] == 0x50 && headerBytes[1] == 0x4B && 
            headerBytes[2] == 0x03 && headerBytes[3] == 0x04; // PK (ZIP)

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

    private async Task<string> SaveResumeAsync(IFormFile file)
    {
        var uploadsFolder = Path.Combine(_environment.ContentRootPath, "Uploads");
        Directory.CreateDirectory(uploadsFolder);

        var uniqueFileName = $"{Guid.NewGuid()}{Path.GetExtension(file.FileName)}";
        var filePath = Path.Combine(uploadsFolder, uniqueFileName);

        using var stream = new FileStream(filePath, FileMode.Create);
        await file.CopyToAsync(stream);

        return uniqueFileName;
    }
}
