using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Models
{
    public class PasswordHistory
    {
        [Key]
        public int PasswordHistoryId { get; set; }

        [Required]
        public int MemberId { get; set; }

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        [Required]
        public DateTime ChangedAt { get; set; } = DateTime.UtcNow;
    }
}