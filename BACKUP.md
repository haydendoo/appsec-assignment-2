# Database backup

Backups are encrypted copies of the SQLite database, stored in the `Backups` folder (or path set in `Backup:Directory`).

## Configuration

- **Backup:Directory** – Folder for backup files (default: `Backups` under the app directory). Use an absolute path to store outside the app (recommended for production).
- **Backup:RetentionCount** – Number of backups to keep; older ones are deleted (default: 7).
- **Backup:IntervalMinutes** – Run a backup every N minutes inside the app (0 = disabled). e.g. 1440 for daily.
- **Encryption:Key** – Same key as used elsewhere in the app; required for backup encryption. Set via User Secrets or environment, never in committed config.

Connection string is taken from `ConnectionStrings:DefaultConnection` unless `Backup:ConnectionString` is set.

## In-app scheduled backup

Set **Backup:IntervalMinutes** (e.g. 1440 for every 24 hours). A background service runs backups on that interval. Set to 0 to disable.

## Manual backup and download (web)

Authenticated users can open **Backup** in the nav to run a backup now and to download existing backups. Files on disk stay encrypted; downloads are decrypted on-the-fly and sent as a `.db` file.

## Running a backup (CLI)

From the project directory:

```bash
dotnet run -- --backup
```

From a published app:

```bash
dotnet appsec-assignment-2.dll --backup
```

Exit code 0 on success, 1 on failure.

## Scheduling with cron (Linux)

Example: run daily at 2:00 AM. Use the published app path and the app’s working directory.

```cron
0 2 * * * cd /var/www/yourapp && dotnet /var/www/yourapp/appsec-assignment-2.dll --backup
```

Or with `dotnet run` (project directory must be correct):

```cron
0 2 * * * cd /path/to/appsec-assignment-2 && dotnet run -- --backup
```

## Windows Task Scheduler

1. Create a new task, trigger (e.g. daily at 2:00 AM).
2. Action: Start a program.
   - Program: `dotnet`
   - Arguments: `run -- --backup` (if from project folder) or `appsec-assignment-2.dll --backup` (if from publish folder).
   - Start in: project or publish directory.

## Restore

Backup files are AES-encrypted. To restore:

1. Use the same `Encryption:Key` as when the backup was created.
2. Decrypt via `DatabaseBackupService.DecryptBackup(backupFilePath)` (e.g. from a small console or admin tool), then write the returned bytes to a new `.db` file and point the app at it, or replace `app.db` when the app is stopped.

## Security

- Store backup directory outside the web root and restrict filesystem permissions to the app/service account only.
- Keep `Encryption:Key` in User Secrets or environment variables; do not commit it.
- The `Backups` folder is in `.gitignore` so encrypted backups are not committed.
