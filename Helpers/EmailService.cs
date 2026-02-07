using System;
using System.Net;
using System.Net.Mail;
using System.Security;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

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
            // Read allowed base URL from configuration (EmailSettings:AllowedBaseUrl)
            var allowedBaseUrl = _config["EmailSettings:AllowedBaseUrl"] ?? "https://localhost:7002";

            // Validate link: must be absolute HTTPS and under the configured base URL
            if (!Uri.TryCreate(link, UriKind.Absolute, out var linkUri) ||
                !string.Equals(linkUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                throw new SecurityException("Reset link must be an absolute HTTPS URL.");
            }

            if (!Uri.TryCreate(allowedBaseUrl, UriKind.Absolute, out var allowedUri))
            {
                throw new SecurityException("Configured allowed base URL is invalid.");
            }

            if (!linkUri.AbsoluteUri.StartsWith(allowedUri.AbsoluteUri, StringComparison.OrdinalIgnoreCase))
            {
                // Block links that don't belong to the trusted base URL to prevent open redirects / data exfil
                throw new SecurityException("Potential malicious redirect detected in password reset link.");
            }

            // Use safe display text and HTML-encode the URL to avoid XSS and information leakage
            var safeDisplayText = "Reset Password (link expires in 1 hour)";
            var encodedLink = WebUtility.HtmlEncode(link);

            string body = $"<h3>Password Reset Request</h3>" +
                          $"<p>Please click the link below to reset your password:</p>" +
                          $"<p><a href='{encodedLink}'>{safeDisplayText}</a></p>" +
                          $"<p>This link will expire in 1 hour.</p>";

            await SendEmailAsync(userEmail, "Reset Your Ace Job Agency Password", body);
        }

        public async Task Send2FACodeAsync(string userEmail, string code)
        {
            // HTML-encode the code to avoid injection and don't include any extra sensitive data
            var encodedCode = WebUtility.HtmlEncode(code);

            string body = $"<h3>Security Verification</h3>" +
                          $"<p>Your 2FA code is: <strong>{encodedCode}</strong></p>" +
                          $"<p>This code expires in 5 minutes.</p>";

            await SendEmailAsync(userEmail, "Your Ace Job Agency Security Code", body);
        }

        private async Task SendEmailAsync(string recipientEmail, string subject, string body)
        {
            var emailSettings = _config.GetSection("EmailSettings");

            // Fail early and do not proceed with empty/invalid critical settings
            string senderEmail = emailSettings["SenderEmail"] ?? throw new InvalidOperationException("SenderEmail is not configured.");
            string senderName = emailSettings["SenderName"] ?? "Ace Job Agency";
            string appPassword = emailSettings["AppPassword"] ?? throw new InvalidOperationException("AppPassword is not configured.");
            string smtpServer = emailSettings["SmtpServer"] ?? "smtp.gmail.com";
            string smtpPortStr = emailSettings["SmtpPort"] ?? "587";

            if (!int.TryParse(smtpPortStr, out var smtpPort))
            {
                smtpPort = 587;
            }

            using var mail = new MailMessage
            {
                From = new MailAddress(senderEmail, senderName),
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            };

            try
            {
                mail.To.Add(new MailAddress(recipientEmail));
            }
            catch (FormatException)
            {
                throw new ArgumentException("Recipient email is invalid.", nameof(recipientEmail));
            }

            using var smtp = new SmtpClient(smtpServer, smtpPort)
            {
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(senderEmail, appPassword),
                EnableSsl = true,
                DeliveryMethod = SmtpDeliveryMethod.Network
            };

            try
            {
                await smtp.SendMailAsync(mail);
            }
            catch (SmtpException ex)
            {
                // Avoid logging sensitive contents (body, tokens, credentials). Keep logs generic.
                System.Diagnostics.Debug.WriteLine($"SMTP Error: {ex.StatusCode} - {ex.Message}");
                throw new Exception("The email service failed to send the message. Please check SMTP settings.");
            }
        }
    }
}