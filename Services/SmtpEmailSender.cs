using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Options;

namespace appsec_assignment_2.Services;

public class SmtpEmailSender : IEmailSender
{
    private readonly EmailOptions _options;
    private readonly ILogger<SmtpEmailSender> _logger;

    public SmtpEmailSender(IOptions<EmailOptions> options, ILogger<SmtpEmailSender> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public async Task SendEmailAsync(string to, string subject, string body, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(_options.AppPassword))
        {
            _logger.LogWarning("Email not sent: AppPassword not configured. Set Email:AppPassword in user secrets.");
            return;
        }

        try
        {
            using var client = new SmtpClient(_options.Host, _options.Port)
            {
                EnableSsl = _options.EnableSsl,
                Credentials = new NetworkCredential(_options.FromAddress, _options.AppPassword)
            };

            var message = new MailMessage(_options.FromAddress, to, subject, body)
            {
                From = new MailAddress(_options.FromAddress, _options.FromName),
                IsBodyHtml = true
            };

            await client.SendMailAsync(message, cancellationToken);
            _logger.LogInformation("Email sent to {To}", to);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send email to {To}", to);
        }
    }
}

public class EmailOptions
{
    public const string SectionName = "Email";

    public string Host { get; set; } = "smtp.gmail.com";
    public int Port { get; set; } = 587;
    public bool EnableSsl { get; set; } = true;
    public string FromAddress { get; set; } = string.Empty;
    public string FromName { get; set; } = string.Empty;
    public string AppPassword { get; set; } = string.Empty;
}
