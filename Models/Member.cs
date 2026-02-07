using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AceJobAgency.Models
{
    public class Member
    {
        [Key]
        public int MemberId { get; set; }

        [Required]
        [StringLength(50)]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [StringLength(50)]
        public string LastName { get; set; } = string.Empty;

        [Required]
        [StringLength(10)]
        public string Gender { get; set; } = string.Empty;

        [Required]
        [StringLength(255)]
        public string Nric { get; set; } = string.Empty;

        [Required]
        [StringLength(100)]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        [Required]
        public DateTime DateOfBirth { get; set; }

        [StringLength(500)]
        public string? ResumePath { get; set; }

        [StringLength(1000)]
        public string? WhoAmI { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public DateTime? LastPasswordChange { get; set; }

        public int FailedLoginAttempts { get; set; } = 0;

        public DateTime? AccountLockedUntil { get; set; }

        public DateTime? LastLoginDate { get; set; }

        // Current active session token - for detecting concurrent logins
        [StringLength(100)]
        public string? CurrentSessionToken { get; set; }

        public DateTime? SessionCreatedAt { get; set; }

        // Computed property to return masked NRIC
        [NotMapped] // Tells Entity Framework not to look for this in the DB
        public string MaskedNric { get; set; } = string.Empty;

        public void GenerateMaskedNric(string decryptedNric)
        {
            if (string.IsNullOrEmpty(decryptedNric) || decryptedNric.Length < 9)
            {
                MaskedNric = "********";
                return;
            }
            // S1234567D -> S****567D
            MaskedNric = decryptedNric[0] + "****" + decryptedNric.Substring(decryptedNric.Length - 4);
        }

        public string? ResetToken { get; set; }
        public DateTime? ResetTokenExpiry { get; set; }
    }
}