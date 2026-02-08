using Microsoft.EntityFrameworkCore;
using appsec_assignment_2.Data;
using appsec_assignment_2.Models;

namespace appsec_assignment_2.Services;

public class AuditService
{
    private readonly ApplicationDbContext _context;
    private readonly ILogger<AuditService> _logger;

    public AuditService(ApplicationDbContext context, ILogger<AuditService> logger)
    {
        _context = context;
        _logger = logger;
    }

    private static readonly HashSet<string> SecurityWarningActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "LoginFailed", "AccountLocked", "2FAFailed"
    };

    public async Task LogAsync(string? userId, string action, string? details, HttpContext? httpContext)
    {
        var ipAddress = httpContext?.Connection.RemoteIpAddress?.ToString();
        if (SecurityWarningActions.Contains(action))
            _logger.LogWarning("Security event: {Action} | UserId: {UserId} | IpAddress: {IpAddress} | Details: {Details}",
                action, userId ?? "(none)", ipAddress, details ?? "");
        else
            _logger.LogInformation("Security event: {Action} | UserId: {UserId} | IpAddress: {IpAddress} | Details: {Details}",
                action, userId ?? "(none)", ipAddress, details ?? "");

        try
        {
            var auditLog = new AuditLog
            {
                UserId = userId,
                Action = action,
                Details = details,
                IpAddress = ipAddress,
                UserAgent = httpContext?.Request.Headers.UserAgent.ToString(),
                Timestamp = DateTime.UtcNow
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Audit log failed for action {Action}", action);
        }
    }

    public async Task<List<AuditLog>> GetUserLogsAsync(string userId, int count = 10)
    {
        try
        {
            return await _context.AuditLogs
                .Where(a => a.UserId == userId)
                .OrderByDescending(a => a.Timestamp)
                .Take(count)
                .ToListAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetUserLogsAsync failed for user {UserId}", userId);
            return new List<AuditLog>();
        }
    }

    public async Task<List<AuditLog>> GetUserLoginLogsAsync(string userId, int count = 15)
    {
        try
        {
            return await _context.AuditLogs
                .Where(a => a.UserId == userId && a.Action == "LoginSuccess")
                .OrderByDescending(a => a.Timestamp)
                .Take(count)
                .ToListAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetUserLoginLogsAsync failed for user {UserId}", userId);
            return new List<AuditLog>();
        }
    }
}
