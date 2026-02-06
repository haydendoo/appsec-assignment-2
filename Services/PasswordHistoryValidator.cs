using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using appsec_assignment_2.Data;
using appsec_assignment_2.Models;

namespace appsec_assignment_2.Services;

public class PasswordHistoryValidator : IPasswordValidator<ApplicationUser>
{
    private readonly ApplicationDbContext _context;
    private readonly IConfiguration _configuration;

    public PasswordHistoryValidator(ApplicationDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }

    public async Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user, string? password)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(user.Id))
        {
            return IdentityResult.Success;
        }

        var historyCount = _configuration.GetValue<int>("PasswordPolicy:HistoryCount", 2);

        var recentPasswords = await _context.PasswordHistories
            .Where(p => p.UserId == user.Id)
            .OrderByDescending(p => p.CreatedAt)
            .Take(historyCount)
            .ToListAsync();

        foreach (var history in recentPasswords)
        {
            var verificationResult = manager.PasswordHasher.VerifyHashedPassword(
                user, 
                history.PasswordHash, 
                password
            );

            if (verificationResult == PasswordVerificationResult.Success ||
                verificationResult == PasswordVerificationResult.SuccessRehashNeeded)
            {
                return IdentityResult.Failed(new IdentityError
                {
                    Code = "PasswordRecentlyUsed",
                    Description = $"Cannot reuse any of your last {historyCount} passwords."
                });
            }
        }

        return IdentityResult.Success;
    }
}
