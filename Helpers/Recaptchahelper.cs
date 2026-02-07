using System.Text.Json;
using System.Text.Json.Serialization; // Add this namespace

namespace AceJobAgency.Helpers
{
    public static class ReCaptchaHelper
    {
        public static async Task<bool> VerifyRecaptcha(string token, string secretKey, HttpClient httpClient)
        {
            try
            {
                var response = await httpClient.PostAsync(
                    $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}",
                    null);

                var jsonString = await response.Content.ReadAsStringAsync();

                // Option A: Use case-insensitive options
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var result = JsonSerializer.Deserialize<RecaptchaResponse>(jsonString, options);

                return result?.Success == true && result.Score >= 0.5;
            }
            catch
            {
                return false;
            }
        }

        private class RecaptchaResponse
        {
            [JsonPropertyName("success")] // Maps 'success' from JSON to 'Success' property
            public bool Success { get; set; }

            [JsonPropertyName("score")]
            public double Score { get; set; }

            [JsonPropertyName("action")]
            public string Action { get; set; } = string.Empty;

            [JsonPropertyName("challenge_ts")]
            public DateTime ChallengeTs { get; set; }

            [JsonPropertyName("hostname")]
            public string Hostname { get; set; } = string.Empty;

            [JsonPropertyName("error-codes")]
            public List<string>? ErrorCodes { get; set; }
        }
    }
}