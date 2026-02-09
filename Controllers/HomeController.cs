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
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue) return RedirectToAction("Login", "Account");

            var member = _context.Members.Find(memberId.Value);
            if (member == null) return RedirectToAction("Logout", "Account");

            // 1. Decrypt NRIC and generate masked version for the Model
            var key = _configuration["Encryption:Key"];
            var iv = _configuration["Encryption:IV"];
            string decryptedNric = EncryptionHelper.Decrypt(member.Nric, key, iv);
            member.GenerateMaskedNric(decryptedNric);

            // 2. Map Profile Data to ViewBag
            ViewBag.FullName = $"{member.FirstName} {member.LastName}";
            ViewBag.Email = member.Email;
            ViewBag.WhoAmI = member.WhoAmI;
            ViewBag.Gender = member.Gender;
            ViewBag.DateOfBirth = member.DateOfBirth.ToString("dd MMMM yyyy");

            // 3. Handle Resume Metadata
            ViewBag.HasResume = !string.IsNullOrEmpty(member.ResumePath);
            ViewBag.ResumeFileName = ViewBag.HasResume ? Path.GetFileName(member.ResumePath) : null;

            // 4. Fetch the previous successful login from AuditLogs
            var lastLoginEntry = _context.AuditLogs
                .Where(a => a.MemberId == memberId.Value && a.Action == "Login")
                .OrderByDescending(a => a.CreatedAt)
                .Skip(1)
                .FirstOrDefault();

            ViewBag.LastLogin = lastLoginEntry?.CreatedAt.ToString("f") ?? "This is your first login!";

            return View(member);
        }

        [HttpGet]
        public IActionResult DownloadResume()
        {
            var memberId = HttpContext.Session.GetInt32("MemberId");
            if (!memberId.HasValue) return RedirectToAction("Login", "Account");

            var member = _context.Members.Find(memberId.Value);
            if (member == null || string.IsNullOrEmpty(member.ResumePath)) return NotFound();

            // 1. Clean the DB path: Replace forward slashes with backslashes for Windows
            // and remove the leading slash so Path.Combine doesn't break.
            string dbPath = member.ResumePath.Replace("/", "\\").TrimStart('\\');

            // 2. Combine with the Application Base Path
            var filePath = Path.Combine(Directory.GetCurrentDirectory(), dbPath);

            if (!System.IO.File.Exists(filePath))
            {
                // DEBUG: If it still fails, check if the folder is actually inside wwwroot
                var alternativePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", dbPath);
                if (System.IO.File.Exists(alternativePath))
                {
                    filePath = alternativePath;
                }
                else
                {
                    return NotFound($"File not found. System checked: {filePath}");
                }
            }

            var fileBytes = System.IO.File.ReadAllBytes(filePath);

            // 3. Serve as Inline PDF
            // We clear the headers first to ensure no conflicting content-disposition exists
            Response.Headers.Clear();
            Response.Headers.Add("Content-Disposition", "inline; filename=\"Resume.pdf\"");

            return File(fileBytes, "application/pdf");
        }

        // --- Error & Admin Handlers ---

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public IActionResult Error403() => View();
        public IActionResult Error404() => View();

        [Route("Home/ErrorHandler/{code}")]
        public IActionResult ErrorHandler(int code)
        {
            return code switch
            {
                404 => View("Error404"),
                403 => View("Error403"),
                _ => View("Error")
            };
        }
    }
}