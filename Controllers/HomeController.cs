using AceJobAgency.Data;
using AceJobAgency.Helpers;
using AceJobAgency.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;

namespace AceJobAgency.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        public HomeController(ApplicationDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }
        public IActionResult Index()
        {
            // For Error Demo
            // throw new Exception("Demo Error");

            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue)
            {
                return RedirectToAction("Login", "Account");
            }

            var member = _context.Members.Find(memberId.Value);
            if (member == null) return RedirectToAction("Logout", "Account");

            // Fetch the previous successful login from AuditLogs
            var lastLoginEntry = _context.AuditLogs
                .Where(a => a.MemberId == memberId.Value && a.Action == "Login")
                .OrderByDescending(a => a.CreatedAt)
                .Skip(1) // Skip current login to show the previous one
                .FirstOrDefault();

            ViewBag.FullName = $"{member.FirstName} {member.LastName}";
            ViewBag.Email = member.Email;
            ViewBag.WhoAmI = member.WhoAmI;

            // Format the date or provide a default message for first-time users
            ViewBag.LastLogin = lastLoginEntry?.CreatedAt.ToString("f") ?? "This is your first login!";

            // Inside Index action
            var key = _configuration["Encryption:Key"];
            var iv = _configuration["Encryption:IV"];
            string decryptedNric = EncryptionHelper.Decrypt(member.Nric, key, iv);

            member.GenerateMaskedNric(decryptedNric);

            return View(member);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public IActionResult Error403()
        {
            return View();
        }

        public IActionResult Error404()
        {
            return View();
        }

        [Route("Home/ErrorHandler/{code}")]
        public IActionResult ErrorHandler(int code)
        {
            // Log the error code for internal auditing if needed
            return code switch
            {
                404 => View("Error404"),
                403 => View("Error403"),
                _ => View("Error") // Generic error for 500 etc.
            };
        }

        [HttpGet]
        public IActionResult AdminOnlySettings()
        {
            // 1. Check if user is even logged in
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue) return RedirectToAction("Login", "Account");

            // 2. Simulate a Role check (e.g., checking if Email is the admin email)
            // Replace with your actual admin email or a 'Role' session variable
            var userEmail = HttpContext.Session.GetString("Email");
            bool isAdmin = userEmail == "admin@acejobagency.com";

            if (!isAdmin)
            {
                // This triggers the 403 status code
                // Your middleware in Program.cs will catch this and show Error403.cshtml
                return StatusCode(403);
            }

            return View();
        }
    }
}