using Microsoft.AspNetCore.Identity;
using appsec_assignment_2.Models;

namespace appsec_assignment_2.Middleware;

public class SessionValidationMiddleware
{
    private readonly RequestDelegate _next;

    public SessionValidationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
    {
        if (context.User.Identity?.IsAuthenticated == true)
        {
            var user = await userManager.GetUserAsync(context.User);
            if (user != null)
            {
                var storedSessionId = context.Session.GetString("SessionId");
                
                // If session IDs don't match, sign out (another device logged in)
                if (!string.IsNullOrEmpty(user.CurrentSessionId) && 
                    storedSessionId != user.CurrentSessionId)
                {
                    await signInManager.SignOutAsync();
                    context.Session.Clear();
                    context.Response.Redirect("/Login?message=session_expired");
                    return;
                }
            }
        }

        await _next(context);
    }
}

public static class SessionValidationMiddlewareExtensions
{
    public static IApplicationBuilder UseSessionValidation(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<SessionValidationMiddleware>();
    }
}
