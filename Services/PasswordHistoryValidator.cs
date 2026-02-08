using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using appsec_assignment_2.Data;
using appsec_assignment_2.Models;

namespace appsec_assignment_2.Services;

public class PasswordHistoryValidator : IPasswordValidator<ApplicationUser>
{
    private readonly ApplicationDbContext _context;
    private readonly IConfiguration _configuration;
    private readonly ILogger<PasswordHistoryValidator> _logger;

    public PasswordHistoryValidator(ApplicationDbContext context, IConfiguration configuration, ILogger<PasswordHistoryValidator> logger)
    {
        _context = context;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user, string? password)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(user.Id))
        {
            return IdentityResult.Success;
        }

        try
        {
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
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Password history validation failed for user {UserId}", user.Id);
            return IdentityResult.Success;
        }

        return IdentityResult.Success;
    }
}
