using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using appsec_assignment_2.Data;
using appsec_assignment_2.Models;

namespace appsec_assignment_2.Middleware;

public class SessionValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SessionValidationMiddleware> _logger;

    public SessionValidationMiddleware(RequestDelegate next, ILogger<SessionValidationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ApplicationDbContext dbContext)
    {
        try
        {
            if (context.User.Identity?.IsAuthenticated == true)
            {
                var user = await userManager.GetUserAsync(context.User);
                if (user != null)
                {
                    var sessionAuthToken = context.Session.GetString("AuthToken");
                    var cookieAuthToken = context.Request.Cookies["AuthToken"];

                    if (string.IsNullOrEmpty(sessionAuthToken) ||
                        string.IsNullOrEmpty(cookieAuthToken) ||
                        sessionAuthToken != cookieAuthToken)
                    {
                        await signInManager.SignOutAsync();
                        context.Session.Clear();
                        context.Response.Cookies.Delete("AuthToken");
                        context.Response.Cookies.Delete(".AspNetCore.Session");
                        context.Response.Redirect("/Login?message=session_invalidated");
                        return;
                    }

                    var dbSession = await dbContext.UserSessions
                        .FirstOrDefaultAsync(s => s.UserId == user.Id && s.AuthToken == sessionAuthToken && s.IsActive);

                    if (dbSession == null)
                    {
                        await signInManager.SignOutAsync();
                        context.Session.Clear();
                        context.Response.Cookies.Delete("AuthToken");
                        context.Response.Cookies.Delete(".AspNetCore.Session");
                        context.Response.Redirect("/Login?message=session_invalidated");
                        return;
                    }

                    dbSession.LastActivityAt = DateTime.UtcNow;
                    await dbContext.SaveChangesAsync();
                }
            }

            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Session validation middleware failed");
            await _next(context);
        }
    }
}

public static class SessionValidationMiddlewareExtensions
{
    public static IApplicationBuilder UseSessionValidation(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<SessionValidationMiddleware>();
    }
}
