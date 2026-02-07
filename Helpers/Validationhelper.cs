using System.Text.RegularExpressions;

namespace AceJobAgency.Helpers
{
    public static class ValidationHelper
    {
        public static bool IsValidNric(string nric)
        {
            if (string.IsNullOrWhiteSpace(nric))
                return false;

            // NRIC format: S1234567D (first letter: S/T/F/G, 7 digits, last letter: A-Z)
            var pattern = @"^[STFG]\d{7}[A-Z]$";
            return Regex.IsMatch(nric.ToUpper(), pattern);
        }

        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email;
            }
            catch
            {
                return false;
            }
        }

        public static bool IsValidFileExtension(string fileName, string[] allowedExtensions)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                return false;

            var extension = Path.GetExtension(fileName).ToLower();
            return allowedExtensions.Contains(extension);
        }

        public static bool IsValidFileSize(long fileSize, long maxSizeInBytes)
        {
            return fileSize > 0 && fileSize <= maxSizeInBytes;
        }

        public static int CalculateAge(DateTime dateOfBirth)
        {
            var today = DateTime.Today;
            var age = today.Year - dateOfBirth.Year;
            if (dateOfBirth.Date > today.AddYears(-age))
                age--;
            return age;
        }
    }
}