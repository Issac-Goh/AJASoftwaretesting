using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Models
{
    public class AuditLog
    {
        [Key]
        public int AuditLogId { get; set; }

        public int? MemberId { get; set; }

        [Required]
        [StringLength(100)]
        public string Action { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Details { get; set; }

        [StringLength(45)]
        public string? IpAddress { get; set; }

        [Required]
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}