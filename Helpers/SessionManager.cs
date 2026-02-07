using AceJobAgency.Data;
using AceJobAgency.Models;
using Microsoft.EntityFrameworkCore;

namespace AceJobAgency.Helpers
{
    /// <summary>
    /// Manages user sessions including creation, validation, and concurrent login detection
    /// </summary>
    public class SessionManager
    {
        private readonly ApplicationDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public SessionManager(ApplicationDbContext context, IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
        }

        /// <summary>
        /// Creates a new session for the member
        /// </summary>
        public async Task<string> CreateSessionAsync(int memberId)
        {
            var sessionToken = GenerateSessionToken();
            var httpContext = _httpContextAccessor.HttpContext;

            if (httpContext == null)
                throw new InvalidOperationException("HttpContext is not available");

            // Get client info
            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = httpContext.Request.Headers["User-Agent"].ToString();

            // Create session record
            var userSession = new UserSession
            {
                MemberId = memberId,
                SessionToken = sessionToken,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                CreatedAt = DateTime.UtcNow,
                LastActivityAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(20), // 20 minute timeout
                IsActive = true
            };

            _context.UserSessions.Add(userSession);

            // Update member's current session token
            var member = await _context.Members.FindAsync(memberId);
            if (member != null)
            {
                member.CurrentSessionToken = sessionToken;
                member.SessionCreatedAt = DateTime.UtcNow;
            }

            await _context.SaveChangesAsync();

            // Store in HTTP session
            httpContext.Session.SetString("SessionToken", sessionToken);
            httpContext.Session.SetString("SessionCreatedAt", DateTime.UtcNow.ToString("o"));

            return sessionToken;
        }

        /// <summary>
        /// Validates if the current session is valid
        /// </summary>
        public async Task<bool> ValidateSessionAsync(int memberId, string sessionToken)
        {
            var member = await _context.Members.FindAsync(memberId);
            if (member == null)
                return false;

            // Check if session token matches the member's current token
            if (member.CurrentSessionToken != sessionToken)
            {
                // Session token doesn't match - user logged in elsewhere
                return false;
            }

            // Check session in database
            var session = await _context.UserSessions
                .FirstOrDefaultAsync(s => s.MemberId == memberId &&
                                         s.SessionToken == sessionToken &&
                                         s.IsActive);

            if (session == null)
                return false;

            // Check if session has expired
            if (session.ExpiresAt < DateTime.UtcNow)
            {
                session.IsActive = false;
                await _context.SaveChangesAsync();
                return false;
            }

            // Update last activity and extend expiration
            session.LastActivityAt = DateTime.UtcNow;
            session.ExpiresAt = DateTime.UtcNow.AddMinutes(20);
            await _context.SaveChangesAsync();

            return true;
        }

        /// <summary>
        /// Invalidates all sessions for a member except the current one
        /// </summary>
        public async Task InvalidateOtherSessionsAsync(int memberId, string currentSessionToken)
        {
            var otherSessions = await _context.UserSessions
                .Where(s => s.MemberId == memberId &&
                           s.SessionToken != currentSessionToken &&
                           s.IsActive)
                .ToListAsync();

            foreach (var session in otherSessions)
            {
                session.IsActive = false;
            }

            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// Invalidates the current session (logout)
        /// </summary>
        public async Task InvalidateSessionAsync(int memberId, string sessionToken)
        {
            var session = await _context.UserSessions
                .FirstOrDefaultAsync(s => s.MemberId == memberId &&
                                         s.SessionToken == sessionToken);

            if (session != null)
            {
                session.IsActive = false;
                await _context.SaveChangesAsync();
            }

            // Clear member's current session token
            var member = await _context.Members.FindAsync(memberId);
            if (member != null && member.CurrentSessionToken == sessionToken)
            {
                member.CurrentSessionToken = null;
                member.SessionCreatedAt = null;
                await _context.SaveChangesAsync();
            }
        }

        /// <summary>
        /// Cleans up expired sessions
        /// </summary>
        public async Task CleanupExpiredSessionsAsync()
        {
            var expiredSessions = await _context.UserSessions
                .Where(s => s.IsActive && s.ExpiresAt < DateTime.UtcNow)
                .ToListAsync();

            foreach (var session in expiredSessions)
            {
                session.IsActive = false;
            }

            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// Gets all active sessions for a member
        /// </summary>
        public async Task<List<UserSession>> GetActiveSessionsAsync(int memberId)
        {
            return await _context.UserSessions
                .Where(s => s.MemberId == memberId && s.IsActive)
                .OrderByDescending(s => s.LastActivityAt)
                .ToListAsync();
        }

        /// <summary>
        /// Checks if user has multiple active sessions (concurrent logins)
        /// </summary>
        public async Task<bool> HasConcurrentLoginsAsync(int memberId)
        {
            var activeSessions = await _context.UserSessions
                .CountAsync(s => s.MemberId == memberId &&
                                s.IsActive &&
                                s.ExpiresAt > DateTime.UtcNow);

            return activeSessions > 1;
        }

        /// <summary>
        /// Generates a secure session token
        /// </summary>
        private string GenerateSessionToken()
        {
            return Convert.ToBase64String(Guid.NewGuid().ToByteArray()) +
                   Convert.ToBase64String(Guid.NewGuid().ToByteArray());
        }
    }
}