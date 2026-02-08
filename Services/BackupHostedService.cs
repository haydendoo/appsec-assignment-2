namespace appsec_assignment_2.Services;

public class BackupHostedService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<BackupHostedService> _logger;

    public BackupHostedService(IServiceProvider serviceProvider, ILogger<BackupHostedService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        int intervalMinutes;
        using (var scope = _serviceProvider.CreateScope())
        {
            var options = scope.ServiceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<BackupOptions>>();
            intervalMinutes = options.Value.IntervalMinutes;
        }
        if (intervalMinutes <= 0)
            return;

        _logger.LogInformation("Scheduled backup enabled: every {Minutes} minutes", intervalMinutes);
        var interval = TimeSpan.FromMinutes(intervalMinutes);

        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(interval, stoppingToken);
            if (stoppingToken.IsCancellationRequested)
                break;

            try
            {
                using var backupScope = _serviceProvider.CreateScope();
                var backupService = backupScope.ServiceProvider.GetRequiredService<DatabaseBackupService>();
                await backupService.CreateBackupAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Scheduled backup failed");
            }
        }
    }
}
