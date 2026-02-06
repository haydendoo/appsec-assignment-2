using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using appsec_assignment_2.Models;
using appsec_assignment_2.Services;

namespace appsec_assignment_2.Pages;

public class LogoutModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuditService _auditService;

    public LogoutModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        AuditService auditService)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _auditService = auditService;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var user = await _userManager.GetUserAsync(User);
        
        if (user != null)
        {
            // Clear session ID
            user.CurrentSessionId = null;
            await _userManager.UpdateAsync(user);
            
            await _auditService.LogAsync(user.Id, "Logout", "User logged out", HttpContext);
        }

        // Clear session
        HttpContext.Session.Clear();
        
        await _signInManager.SignOutAsync();
        
        return RedirectToPage("/Login");
    }
}
