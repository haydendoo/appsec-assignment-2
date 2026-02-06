using System.Text.Json;

namespace appsec_assignment_2.Services;

public class RecaptchaService
{
    private readonly HttpClient _httpClient;
    private readonly string _secretKey;
    private readonly ILogger<RecaptchaService> _logger;

    public RecaptchaService(HttpClient httpClient, IConfiguration configuration, ILogger<RecaptchaService> logger)
    {
        _httpClient = httpClient;
        _secretKey = configuration["Recaptcha:SecretKey"] ?? string.Empty;
        _logger = logger;
    }

    public async Task<RecaptchaResponse> VerifyAsync(string token)
    {
        if (string.IsNullOrEmpty(_secretKey))
        {
            _logger.LogWarning("reCAPTCHA secret key not configured, skipping verification");
            return new RecaptchaResponse { Success = true, Score = 1.0f };
        }

        if (string.IsNullOrEmpty(token))
        {
            return new RecaptchaResponse { Success = false, Score = 0 };
        }

        try
        {
            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "secret", _secretKey },
                { "response", token }
            });

            var response = await _httpClient.PostAsync(
                "https://www.google.com/recaptcha/api/siteverify", 
                content
            );

            var json = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<RecaptchaApiResponse>(json);

            return new RecaptchaResponse
            {
                Success = result?.Success ?? false,
                Score = result?.Score ?? 0
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying reCAPTCHA");
            return new RecaptchaResponse { Success = false, Score = 0 };
        }
    }

    private class RecaptchaApiResponse
    {
        public bool Success { get; set; }
        public float Score { get; set; }
        public string? Action { get; set; }
        public string? Hostname { get; set; }
    }
}

public class RecaptchaResponse
{
    public bool Success { get; set; }
    public float Score { get; set; }
}
