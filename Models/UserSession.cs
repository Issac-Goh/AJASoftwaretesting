using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AceJobAgency.Models
{
    /// <summary>
    /// Tracks active user sessions for concurrent login detection
    /// </summary>
    public class UserSession
    {
        [Key]
        public int SessionId { get; set; }

        [Required]
        public int MemberId { get; set; }

        [Required]
        [StringLength(100)]
        public string SessionToken { get; set; } = string.Empty;

        [StringLength(50)]
        public string? IpAddress { get; set; }

        [StringLength(500)]
        public string? UserAgent { get; set; }

        [Required]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        [Required]
        public DateTime LastActivityAt { get; set; } = DateTime.UtcNow;

        [Required]
        public DateTime ExpiresAt { get; set; }

        public bool IsActive { get; set; } = true;

        // Navigation property
        [ForeignKey("MemberId")]
        public Member? Member { get; set; }
    }
}