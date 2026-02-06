# Web Application Security Checklist

## Registration and User Data Management
- [x] Implement successful saving of member info into the database
  - *Implemented: ApplicationUser entity with EF Core, saved to SQLite database*
- [x] Check for duplicate email addresses and handle appropriately
  - *Implemented: Identity's RequireUniqueEmail + manual check in Register.cshtml.cs*
- [x] Implement strong password requirements:
  - [x] Minimum 12 characters
    - *Implemented: options.Password.RequiredLength = 12 in Program.cs*
  - [x] Combination of lowercase, uppercase, numbers, and special characters
    - *Implemented: Identity PasswordOptions + RegularExpression validation*
  - [x] Provide feedback on password strength
    - *Implemented: password-strength.js with visual strength meter*
  - [x] Implement both client-side and server-side password checks
    - *Implemented: jQuery validation (client) + Data Annotations (server)*
- [x] Encrypt sensitive user data in the database (e.g., NRIC, credit card numbers)
  - *Implemented: EncryptionService using AES-256 for NRIC encryption*
- [x] Implement proper password hashing and storage
  - *Implemented: Identity uses PBKDF2 by default*
- [x] Implement file upload restrictions (e.g., .docx, .pdf, or .jpg only)
  - *Implemented: Extension whitelist + magic byte validation in Register.cshtml.cs*

## Session Management
- [x] Create a secure session upon successful login
  - *Implemented: Identity cookie auth with HttpOnly, Secure, SameSite=Strict*
- [x] Implement session timeout
  - *Implemented: ExpireTimeSpan = 30 minutes with SlidingExpiration*
- [x] Route to homepage/login page after session timeout
  - *Implemented: LoginPath configured in cookie settings*
- [x] Detect and handle multiple logins from different devices/browser tabs
  - *Implemented: CurrentSessionId tracking + SessionValidationMiddleware*

## Login/Logout Security
- [x] Implement proper login functionality
  - *Implemented: Login.cshtml with SignInManager*
- [x] Implement rate limiting (e.g., account lockout after 3 failed login attempts)
  - *Implemented: MaxFailedAccessAttempts = 3, LockoutTimeSpan = 15 minutes*
- [x] Perform proper and safe logout (clear session and redirect to login page)
  - *Implemented: Logout.cshtml.cs clears session and signs out*
- [x] Implement audit logging (save user activities in the database)
  - *Implemented: AuditService logs all security events to AuditLogs table*
- [x] Redirect to homepage after successful login, displaying user info
  - *Implemented: Index.cshtml shows user info with decrypted NRIC*

## Anti-Bot Protection
- [x] Implement Google reCAPTCHA v3 service
  - *Implemented: RecaptchaService with configurable site/secret keys*

## Input Validation and Sanitization
- [x] Prevent injection attacks (e.g., SQL injection)
  - *Implemented: EF Core parameterized queries (no raw SQL)*
- [x] Implement Cross-Site Request Forgery (CSRF) protection
  - *Implemented: Razor Pages automatic AntiForgeryToken*
- [x] Prevent Cross-Site Scripting (XSS) attacks
  - *Implemented: Razor auto-encoding + CSP headers*
- [x] Perform proper input sanitization, validation, and verification for all user inputs
  - *Implemented: Data Annotations on all ViewModels*
- [x] Implement both client-side and server-side input validation
  - *Implemented: jQuery Validation (client) + Data Annotations (server)*
- [x] Display error or warning messages for improper input
  - *Implemented: asp-validation-for and asp-validation-summary*
- [x] Perform proper encoding before saving data into the database
  - *Implemented: EF Core handles parameterization automatically*

## Error Handling
- [x] Implement graceful error handling on all pages
  - *Implemented: UseExceptionHandler + custom Error.cshtml*
- [x] Create and display custom error pages (e.g., 404, 403)
  - *Implemented: Pages/Errors/404.cshtml and 403.cshtml*

## Software Testing and Security Analysis
- [ ] Perform source code analysis using external tools (e.g., GitHub)
  - *To do: Enable GitHub Dependabot (already configured in .github/dependabot.yml)*
- [ ] Address security vulnerabilities identified in the source code
  - *To do: Review Dependabot alerts when available*

## Advanced Security Features
- [x] Implement automatic account recovery after lockout period
  - *Implemented: LockoutTimeSpan = 15 minutes auto-unlock*
- [x] Enforce password history (avoid password reuse, max 2 password history)
  - *Implemented: PasswordHistoryValidator checks last 2 passwords*
- [x] Implement change password functionality
  - *Implemented: ChangePassword.cshtml with minimum age check*
- [x] Implement reset password functionality (using email link or SMS)
  - *Implemented: ForgotPassword + ResetPassword with token (logs to console)*
- [x] Enforce minimum and maximum password age policies
  - *Implemented: MinimumAgeMinutes and MaximumAgeDays in config*
- [x] Implement Two-Factor Authentication (2FA)
  - *Implemented: TwoFactorSetup with QR code + TwoFactorVerify*

## General Security Best Practices
- [x] Use HTTPS for all communications
  - *Implemented: UseHttpsRedirection + UseHsts + Secure cookies*
- [x] Implement proper access controls and authorization
  - *Implemented: [Authorize] attribute on protected pages*
- [x] Keep all software and dependencies up to date
  - *Implemented: Dependabot configured for automated updates*
- [x] Follow secure coding practices
  - *Implemented: Following OWASP guidelines throughout*
- [ ] Regularly backup and securely store user data
  - *Note: SQLite database can be backed up by copying app.db*
- [x] Implement logging and monitoring for security events
  - *Implemented: AuditService logs all security-relevant events*

## Documentation and Reporting
- [ ] Prepare a report on implemented security features
  - *To do: Write report based on this checklist*
- [x] Complete and submit the security checklist
  - *Completed: All core features implemented*

## Security Headers Implemented
- [x] X-Content-Type-Options: nosniff
- [x] X-Frame-Options: DENY
- [x] X-XSS-Protection: 1; mode=block
- [x] Referrer-Policy: strict-origin-when-cross-origin
- [x] Content-Security-Policy

Remember to test each security feature thoroughly and ensure they work as expected in your web application.
