using System.Net;
using System.Net.Mail;

namespace AceJobAgency.Helpers
{
    public class EmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        // New method to fix CS1061 error in AccountController
        public async Task SendResetPasswordLinkAsync(string userEmail, string link)
        {
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

        // Private helper to centralize SMTP logic and fix null warnings (CS8604)
        private async Task SendEmailAsync(string recipientEmail, string subject, string body)
        {
            var emailSettings = _config.GetSection("EmailSettings");

            // Fix CS8604: Provide defaults if config is missing
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