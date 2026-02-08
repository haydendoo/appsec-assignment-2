using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using appsec_assignment_2.Data;
using appsec_assignment_2.Models;
using appsec_assignment_2.Services;

namespace appsec_assignment_2.Pages;

[ValidateAntiForgeryToken]
public class LogoutModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuditService _auditService;
    private readonly ApplicationDbContext _dbContext;
    private readonly ILogger<LogoutModel> _logger;

    public LogoutModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        AuditService auditService,
        ApplicationDbContext dbContext,
        ILogger<LogoutModel> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditService = auditService;
        _dbContext = dbContext;
        _logger = logger;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        try
        {
            var user = await _userManager.GetUserAsync(User);
            var currentAuthToken = HttpContext.Session.GetString("AuthToken");

            if (user != null)
            {
                if (!string.IsNullOrEmpty(currentAuthToken))
                {
                    var session = await _dbContext.UserSessions
                        .FirstOrDefaultAsync(s => s.UserId == user.Id && s.AuthToken == currentAuthToken);
                    if (session != null)
                    {
                        session.IsActive = false;
                        await _dbContext.SaveChangesAsync();
                    }
                }

                await _auditService.LogAsync(user.Id, "Logout", "User logged out", HttpContext);
            }

            HttpContext.Session.Clear();

            Response.Cookies.Delete("AuthToken");
            Response.Cookies.Delete(".AspNetCore.Session");

            foreach (var cookie in Request.Cookies.Keys)
            {
                Response.Cookies.Delete(cookie);
            }

            await _signInManager.SignOutAsync();

            return RedirectToPage("/Login");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Logout OnPost failed");
            try
            {
                await _signInManager.SignOutAsync();
            }
            catch
            {
                // Ignore
            }
            return RedirectToPage("/Login");
        }
    }
}
