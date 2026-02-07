using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AceJobAgency.Data;
using AceJobAgency.Models;
using AceJobAgency.Helpers;
using System.Text.Encodings.Web;
using System.Security.Cryptography;
using System.Text;

namespace AceJobAgency.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IWebHostEnvironment _environment;
        private readonly SessionManager _sessionManager;
        private readonly EmailService _emailService;

        public AccountController(
            ApplicationDbContext context,
            IConfiguration configuration,
            IHttpClientFactory httpClientFactory,
            IWebHostEnvironment environment,
            SessionManager sessionManager,
            EmailService emailService)
        {
            _context = context;
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
            _environment = environment;
            _sessionManager = sessionManager;
            _emailService = emailService;
        }

        [HttpGet]
        public IActionResult CheckSessionStatus()
        {
            var sessionToken = HttpContext.Session.GetString("SessionToken");
            var memberId = HttpContext.Session.GetInt32("MemberId");

            if (!memberId.HasValue || string.IsNullOrEmpty(sessionToken))
            {
                return Json(new { valid = false });
            }

            // Check if this token matches the one in the database
            var member = _context.Members.AsNoTracking().FirstOrDefault(m => m.MemberId == memberId);

            if (member == null || member.CurrentSessionToken != sessionToken)
            {
                return Json(new { valid = false });
            }

            return Json(new { valid = true });
        }

        // GET: Account/Login
        [HttpGet]
        public IActionResult Login(bool expired = false)
        {
            if (HttpContext.Session.GetInt32("MemberId").HasValue)
            {
                return RedirectToAction("Index", "Home");
            }

            if (expired)
            {
                TempData["WarningMessage"] = "Your session has expired. Please login again.";
            }

            return View();
        }

        // POST: Account/Login
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            // 1. Verify reCAPTCHA (Existing)
            var httpClient = _httpClientFactory.CreateClient();
            var secretKey = _configuration["ReCaptcha:SecretKey"];
            var isRecaptchaValid = await ReCaptchaHelper.VerifyRecaptcha(
                model.RecaptchaToken ?? "", secretKey ?? "", httpClient);

            if (!isRecaptchaValid)
            {
                ModelState.AddModelError("", "reCAPTCHA validation failed");
                return View(model);
            }

            if (!ModelState.IsValid) return View(model);

            var member = await _context.Members.FirstOrDefaultAsync(m => m.Email == model.Email);

            if (member == null)
            {
                await LogAudit(null, "Failed Login - Invalid Email", model.Email);
                ModelState.AddModelError("", "Invalid email or password");
                return View(model);
            }

            // 2. Check Lockout (Existing)
            if (member.AccountLockedUntil.HasValue && member.AccountLockedUntil > DateTime.UtcNow)
            {
                var remainingMinutes = (member.AccountLockedUntil.Value - DateTime.UtcNow).TotalMinutes;
                TempData["ErrorMessage"] = $"Account is locked. Try again in {Math.Ceiling(remainingMinutes)} minutes.";
                return View(model);
            }

            // 3. Verify Password (Existing)
            if (!PasswordHelper.VerifyPassword(model.Password, member.PasswordHash))
            {
                member.FailedLoginAttempts++;
                if (member.FailedLoginAttempts >= 3)
                {
                    member.AccountLockedUntil = DateTime.UtcNow.AddMinutes(15);
                    member.FailedLoginAttempts = 0;
                    await LogAudit(member.MemberId, "Account Locked", "Too many failed login attempts");
                    TempData["ErrorMessage"] = "Account locked for 15 minutes.";
                }
                else
                {
                    await LogAudit(member.MemberId, "Failed Login - Wrong Password", model.Email);
                    ModelState.AddModelError("", "Invalid email or password");
                }
                await _context.SaveChangesAsync();
                return View(model);
            }

            // 4. TRIGGER 2FA (New)
            // Generate 6-digit code
            string twoFactorCode = new Random().Next(100000, 999999).ToString();

            // Store temporary data in session (User is NOT fully logged in yet)
            HttpContext.Session.SetString("2FACode", twoFactorCode);
            HttpContext.Session.SetInt32("PendingMemberId", member.MemberId);

            // Set expiry for the code (optional: 5 minutes from now)
            HttpContext.Session.SetString("2FAExpiry", DateTime.UtcNow.AddMinutes(5).ToString("o"));

            // Send the real email
            try
            {
                await _emailService.Send2FACodeAsync(member.Email, twoFactorCode);
                await LogAudit(member.MemberId, "2FA Code Sent", $"Code sent to {member.Email}");
            }
            catch (Exception ex)
            {
                // Log the error (ex) here
                ModelState.AddModelError("", "We encountered an error sending your verification email. Please try again.");
                return View(model);
            }

            // Redirect to the verification page
            return RedirectToAction("Verify2FA");
        }

        [HttpGet]
        public IActionResult Verify2FA()
        {
            // Ensure there is a pending login, otherwise kick them back to login
            if (!HttpContext.Session.GetInt32("PendingMemberId").HasValue)
                return RedirectToAction("Login");

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Verify2FA(string code)
        {
            var pendingId = HttpContext.Session.GetInt32("PendingMemberId");
            var actualCode = HttpContext.Session.GetString("2FACode");
            var expiryStr = HttpContext.Session.GetString("2FAExpiry");

            if (string.IsNullOrEmpty(actualCode) || !pendingId.HasValue)
                return RedirectToAction("Login");

            // 1. Check Expiry
            if (DateTime.TryParse(expiryStr, out var expiry) && DateTime.UtcNow > expiry)
            {
                await LogAudit(pendingId, "2FA Code Expired", "User attempted to use an expired code.");
                ModelState.AddModelError("", "The code has expired. Please login again.");
                return View();
            }

            // 2. Brute-Force Protection (Attempt Tracking)
            int attempts = HttpContext.Session.GetInt32("2FAAttempts") ?? 0;

            if (code == actualCode)
            {
                var member = await _context.Members.FindAsync(pendingId.Value);

                // Success! Perform Final Session Management
                await _sessionManager.InvalidateOtherSessionsAsync(member.MemberId, "");
                var sessionToken = await _sessionManager.CreateSessionAsync(member.MemberId);

                member.FailedLoginAttempts = 0; // Reset both password and 2FA failures
                member.AccountLockedUntil = null;
                await _context.SaveChangesAsync();

                // Finalize HTTP Session
                HttpContext.Session.SetInt32("MemberId", member.MemberId);
                HttpContext.Session.SetString("FullName", $"{member.FirstName} {member.LastName}");
                HttpContext.Session.SetString("Email", member.Email);
                HttpContext.Session.SetString("SessionToken", sessionToken);

                // Clear 2FA temp data
                HttpContext.Session.Remove("2FACode");
                HttpContext.Session.Remove("PendingMemberId");
                HttpContext.Session.Remove("2FAExpiry");
                HttpContext.Session.Remove("2FAAttempts"); // Clear attempts on success

                await LogAudit(member.MemberId, "Successful 2FA Verification", member.Email);

                if (member.LastPasswordChange == null || (DateTime.UtcNow - member.LastPasswordChange.Value).TotalDays > 90)
                {
                    TempData["WarningMessage"] = "Your password has expired. Please change it.";
                    return RedirectToAction("ChangePassword");
                }

                return RedirectToAction("Index", "Home");
            }

            // 3. Handle Failure and Lockout
            attempts++;
            HttpContext.Session.SetInt32("2FAAttempts", attempts);

            await LogAudit(pendingId, "Failed 2FA Attempt", $"Attempt {attempts} of 3");

            if (attempts >= 3)
            {
                var member = await _context.Members.FindAsync(pendingId.Value);
                if (member != null)
                {
                    // Lock account for 5 minutes
                    member.AccountLockedUntil = DateTime.UtcNow.AddMinutes(5);
                    await _context.SaveChangesAsync();
                    await LogAudit(member.MemberId, "Account Locked", "Locked due to 3 failed 2FA attempts.");
                }

                HttpContext.Session.Clear(); // Force restart login flow
                TempData["Error"] = "Too many failed attempts. Account locked for 5 minutes.";
                return RedirectToAction("Login");
            }

            ModelState.AddModelError("", $"Invalid verification code. {3 - attempts} attempts remaining.");
            return View();
        }

        // GET: Account/Register
        [HttpGet]
        public IActionResult Register()
        {
            if (HttpContext.Session.GetInt32("MemberId").HasValue)
            {
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        // POST: Account/Register
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Verify reCAPTCHA
            var httpClient = _httpClientFactory.CreateClient();
            var secretKey = _configuration["ReCaptcha:SecretKey"];
            var isRecaptchaValid = await ReCaptchaHelper.VerifyRecaptcha(
                model.RecaptchaToken ?? "", secretKey ?? "", httpClient);

            if (!isRecaptchaValid)
            {
                ModelState.AddModelError("", "reCAPTCHA validation failed");
                return View(model);
            }

            // Normalize email to prevent duplicates caused by casing/whitespace
            var normalizedEmail = (model.Email ?? string.Empty).Trim().ToLowerInvariant();

            // Check if email already exists (normalized)
            if (await _context.Members.AnyAsync(m => m.Email != null && m.Email.ToLower() == normalizedEmail))
            {
                ModelState.AddModelError("Email", "Email already registered");
                return View(model);
            }

            // Get keys for duplicate check
            var encryptionKey = _configuration["Encryption:Key"] ?? "";
            var encryptionIv = _configuration["Encryption:IV"] ?? "";

            // Check if NRIC already exists
            var encryptedInputNric = EncryptionHelper.Encrypt(model.Nric, encryptionKey, encryptionIv);
            if (await _context.Members.AnyAsync(m => m.Nric == encryptedInputNric))
            {
                ModelState.AddModelError("Nric", "NRIC already registered");
                return View(model);
            }

            // Validate file
            if (model.Resume != null)
            {
                var allowedExtensions = new[] { ".pdf", ".docx" };
                if (!ValidationHelper.IsValidFileExtension(model.Resume.FileName, allowedExtensions))
                {
                    ModelState.AddModelError("Resume", "Only PDF and DOCX files are allowed");
                    return View(model);
                }

                if (!ValidationHelper.IsValidFileSize(model.Resume.Length, 5 * 1024 * 1024))
                {
                    ModelState.AddModelError("Resume", "File size cannot exceed 5MB");
                    return View(model);
                }
            }

            // Save resume file
            string? resumePath = null;
            if (model.Resume != null)
            {
                var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads", "resumes");
                Directory.CreateDirectory(uploadsFolder);

                var uniqueFileName = $"{Guid.NewGuid()}_{model.Resume.FileName}";
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                using (var fileStream = new FileStream(filePath, FileMode.Create))
                {
                    await model.Resume.CopyToAsync(fileStream);
                }

                resumePath = $"/uploads/resumes/{uniqueFileName}";
            }

            // Encrypt sensitive data
            var encryptedNric = EncryptionHelper.Encrypt(
                model.Nric, _configuration["Encryption:Key"], _configuration["Encryption:IV"]
            ); 

            // Create member
            var member = new Member
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
                Gender = model.Gender,
                Nric = encryptedNric,
                Email = model.Email,
                PasswordHash = PasswordHelper.HashPassword(model.Password),
                DateOfBirth = model.DateOfBirth,
                ResumePath = resumePath,
                // SANITIZE HERE: Encodes <script> into &lt;script&gt;
                WhoAmI = HtmlEncoder.Default.Encode(model.WhoAmI),
                CreatedAt = DateTime.UtcNow,
                LastPasswordChange = DateTime.UtcNow
            };

            _context.Members.Add(member);
            await _context.SaveChangesAsync();

            // Add to password history
            var passwordHistory = new PasswordHistory
            {
                MemberId = member.MemberId,
                PasswordHash = member.PasswordHash,
                ChangedAt = DateTime.UtcNow
            };
            _context.PasswordHistories.Add(passwordHistory);
            await _context.SaveChangesAsync();

            await LogAudit(member.MemberId, "Registration", model.Email);

            TempData["SuccessMessage"] = "Registration successful! Please login.";
            return RedirectToAction("Login");
        }

        // GET: Account/ChangePassword
        [HttpGet]
        public async Task<IActionResult> ChangePassword()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue)
            {
                return RedirectToAction("Login");
            }

            // Validate session
            var sessionToken = HttpContext.Session.GetString("SessionToken");
            if (string.IsNullOrEmpty(sessionToken) || !await _sessionManager.ValidateSessionAsync(memberId.Value, sessionToken))
            {
                HttpContext.Session.Clear();
                TempData["WarningMessage"] = "Your session has expired or you've logged in from another device.";
                return RedirectToAction("Login");
            }

            return View();
        }

        // POST: Account/ChangePassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue)
            {
                return RedirectToAction("Login");
            }

            // 1. Validate Session (Prevents session hijacking/concurrent bypass)
            var sessionToken = HttpContext.Session.GetString("SessionToken");
            if (string.IsNullOrEmpty(sessionToken) || !await _sessionManager.ValidateSessionAsync(memberId.Value, sessionToken))
            {
                HttpContext.Session.Clear();
                TempData["WarningMessage"] = "Your session has expired or you've logged in from another device.";
                return RedirectToAction("Login");
            }

            if (!ModelState.IsValid) return View(model);

            var member = await _context.Members.FindAsync(memberId.Value);
            if (member == null) return RedirectToAction("Login");

            // 2. Verify Current Password
            if (!PasswordHelper.VerifyPassword(model.CurrentPassword, member.PasswordHash))
            {
                ModelState.AddModelError("CurrentPassword", "Current password is incorrect.");
                return View(model);
            }

            // 3. 5-Minute Cooldown Check
            if (member.LastPasswordChange.HasValue)
            {
                var minutesSinceChange = (DateTime.UtcNow - member.LastPasswordChange.Value).TotalMinutes;
                if (minutesSinceChange < 5)
                {
                    ModelState.AddModelError("", $"Security Policy: Please wait {5 - (int)minutesSinceChange} more minutes before changing your password again.");
                    return View(model);
                }
            }

            // 4. "Last 2 Passwords" History Check
            string newPasswordHash = PasswordHelper.HashPassword(model.NewPassword);

            // A. Check against the CURRENT password
            if (newPasswordHash == member.PasswordHash)
            {
                ModelState.AddModelError("NewPassword", "New password cannot be the same as your current password.");
                return View(model);
            }

            // B. Check against the PREVIOUS password in history
            var lastHistoryEntry = await _context.PasswordHistories
                .Where(ph => ph.MemberId == memberId.Value)
                .OrderByDescending(ph => ph.ChangedAt)
                .FirstOrDefaultAsync();

            if (lastHistoryEntry != null && lastHistoryEntry.PasswordHash == newPasswordHash)
            {
                ModelState.AddModelError("NewPassword", "You cannot reuse your last 2 passwords.");
                return View(model);
            }

            // 5. Update Record & Save History
            // We add the OLD password to history before we overwrite the member record
            var passwordHistory = new PasswordHistory
            {
                MemberId = member.MemberId,
                PasswordHash = member.PasswordHash, // Store the hash we are replacing
                ChangedAt = DateTime.UtcNow
            };
            _context.PasswordHistories.Add(passwordHistory);

            // Update member with new data
            member.PasswordHash = newPasswordHash;
            member.LastPasswordChange = DateTime.UtcNow;

            // Single save for both changes (Atomic transaction)
            await _context.SaveChangesAsync();

            await LogAudit(member.MemberId, "Password Changed", "User successfully updated their password.");

            TempData["SuccessMessage"] = "Password changed successfully!";
            return RedirectToAction("Index", "Home");
        }

        // GET: Account/Logout
        public async Task<IActionResult> Logout()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            var sessionToken = HttpContext.Session.GetString("SessionToken");

            if (memberId.HasValue && !string.IsNullOrEmpty(sessionToken))
            {
                // Invalidate session in database
                await _sessionManager.InvalidateSessionAsync(memberId.Value, sessionToken);
                await LogAudit(memberId.Value, "Logout", "User initiated logout");
            }

            HttpContext.Session.Clear();
            TempData["InfoMessage"] = "You have been logged out.";
            return RedirectToAction("Login");
        }

        // API endpoint to check session status (for client-side timeout detection)
        [HttpGet]
        public async Task<IActionResult> CheckSession()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            var sessionToken = HttpContext.Session.GetString("SessionToken");

            if (!memberId.HasValue || string.IsNullOrEmpty(sessionToken))
            {
                return Json(new { isValid = false, reason = "no_session" });
            }

            var isValid = await _sessionManager.ValidateSessionAsync(memberId.Value, sessionToken);

            if (!isValid)
            {
                HttpContext.Session.Clear();
                return Json(new { isValid = false, reason = "expired_or_concurrent" });
            }

            // Get session timeout remaining
            var loginTimeStr = HttpContext.Session.GetString("LoginTime");
            var timeRemaining = 20; // default 20 minutes

            if (!string.IsNullOrEmpty(loginTimeStr) && DateTime.TryParse(loginTimeStr, out var loginTime))
            {
                var elapsed = (DateTime.UtcNow - loginTime).TotalMinutes;
                timeRemaining = Math.Max(0, 20 - (int)elapsed);
            }

            return Json(new
            {
                isValid = true,
                timeRemaining = timeRemaining,
                lastActivity = DateTime.UtcNow.ToString("o")
            });
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            // Do NOT check for MemberId here. 
            // We want logged-out users to access this.
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(string email)                                   
        {
            var member = await _context.Members.FirstOrDefaultAsync(m => m.Email == email);
            if (member != null)
            {
                // Generate a unique URL-safe token
                string token = Guid.NewGuid().ToString();
                member.ResetToken = token;
                member.ResetTokenExpiry = DateTime.UtcNow.AddHours(1); // Link expires in 1 hour
                await _context.SaveChangesAsync();

                // Generate the reset link
                var resetLink = Url.Action("ResetPassword", "Account", new { token = token }, Request.Scheme);

                // Send Email
                await _emailService.SendResetPasswordLinkAsync(member.Email, resetLink);
                await LogAudit(member.MemberId, "Reset Link Sent", $"Sent to {email}");
            }

            // Always show success to prevent email enumeration (privacy)
            TempData["SuccessMessage"] = "If an account exists, a reset link has been sent.";
            return RedirectToAction("Login");
        }

        [HttpGet]
        public IActionResult ResetPassword(string token)
        {
            var member = _context.Members.FirstOrDefault(m => m.ResetToken == token && m.ResetTokenExpiry > DateTime.UtcNow);
            if (member == null) return RedirectToAction("Login", new { error = "Invalid or expired token" });

            return View(new ResetPasswordViewModel { Token = token });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            var member = await _context.Members.FirstOrDefaultAsync(m => m.ResetToken == model.Token && m.ResetTokenExpiry > DateTime.UtcNow);
            if (member == null) return RedirectToAction("Login");

            // Enforce Password History Check
            string newHash = PasswordHelper.HashPassword(model.NewPassword);
            // 1. Fetch the user's password history using your 'ChangedAt' property
            var history = await _context.PasswordHistories
                .Where(ph => ph.MemberId == member.MemberId)
                .OrderByDescending(ph => ph.ChangedAt)
                .Take(2)
                .ToListAsync();

            // 2. Check if the new password matches the current one
            if (PasswordHelper.VerifyPassword(model.NewPassword, member.PasswordHash))
            {
                ModelState.AddModelError("NewPassword", "You cannot use your current password.");
                return View(model);
            }

            // 3. Check against the last 2 stored history records using your 'PasswordHash' property
            foreach (var oldPass in history)
            {
                if (PasswordHelper.VerifyPassword(model.NewPassword, oldPass.PasswordHash))
                {
                    ModelState.AddModelError("NewPassword", "You cannot reuse your last 2 passwords.");
                    return View(model);
                }
            }

            // 4. Save the current hash to history before updating to the new one
            _context.PasswordHistories.Add(new PasswordHistory
            {
                MemberId = member.MemberId,
                PasswordHash = member.PasswordHash,
                ChangedAt = DateTime.UtcNow
            });

            // Update the actual member record
            member.PasswordHash = newHash;

            member.PasswordHash = newHash;
            member.ResetToken = null; // Invalidate token after use
            member.ResetTokenExpiry = null;
            member.LastPasswordChange = DateTime.UtcNow;

            await _context.SaveChangesAsync();
            return RedirectToAction("Login");
        }

        // Helper method to log audit
        private async Task LogAudit(int? memberId, string action, string details)
        {
            var auditLog = new AuditLog
            {
                MemberId = memberId,
                Action = action,
                Details = details,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                CreatedAt = DateTime.UtcNow
            };

            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
        }
    }
}