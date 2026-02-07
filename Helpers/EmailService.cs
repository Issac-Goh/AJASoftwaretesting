using System.Net;
using System.Net.Mail;
using System.Security; // Added for SecurityException

namespace AceJobAgency.Helpers
{
    public class EmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendResetPasswordLinkAsync(string userEmail, string link)
        {
            // --- SECURITY FIX START ---
            // 1. Define your allowed base URL (get this from appsettings.json in a real app)
            var allowedDomain = "https://localhost:7002";

            // 2. Validate the link starts with your trusted domain
            if (string.IsNullOrEmpty(link) || !link.StartsWith(allowedDomain, StringComparison.OrdinalIgnoreCase))
            {
                // If the link is manipulated, we block the email and throw an error
                throw new SecurityException("Potential malicious redirect detected in password reset link.");
            }
            // --- SECURITY FIX END ---

            string body = $"<h3>Password Reset Request</h3>" +
                          $"<p>Please click the link below to reset your password:</p>" +
                          $"<p><a href='{link}'>Reset Password Now</a></p>" +
                          $"<p>This link will expire in 1 hour.</p>";

            await SendEmailAsync(userEmail, "Reset Your Ace Job Agency Password", body);
        }

        public async Task Send2FACodeAsync(string userEmail, string code)
        {
            string body = $"<h3>Security Verification</h3>" +
                          $"<p>Your 2FA code is: <strong>{code}</strong></p>" +
                          $"<p>This code expires in 5 minutes.</p>";

            await SendEmailAsync(userEmail, "Your Ace Job Agency Security Code", body);
        }

        private async Task SendEmailAsync(string recipientEmail, string subject, string body)
        {
            var emailSettings = _config.GetSection("EmailSettings");

            string senderEmail = emailSettings["SenderEmail"] ?? "";
            string senderName = emailSettings["SenderName"] ?? "Ace Job Agency";
            string appPassword = emailSettings["AppPassword"] ?? "";
            string smtpServer = emailSettings["SmtpServer"] ?? "smtp.gmail.com";
            string smtpPortStr = emailSettings["SmtpPort"] ?? "587";

            var mail = new MailMessage
            {
                From = new MailAddress(senderEmail, senderName),
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            };
            mail.To.Add(recipientEmail);

            using var smtp = new SmtpClient(smtpServer, int.Parse(smtpPortStr))
            {
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(senderEmail, appPassword),
                EnableSsl = true,
                TargetName = "STARTTLS/smtp.gmail.com",
                DeliveryMethod = SmtpDeliveryMethod.Network
            };

            try
            {
                await smtp.SendMailAsync(mail);
            }
            catch (SmtpException ex)
            {
                System.Diagnostics.Debug.WriteLine($"SMTP Error: {ex.Message}");
                throw new Exception("The email service failed. Please check SMTP settings.");
            }
        }
    }
}