using AceJobAgency.Data;
using AceJobAgency.Helpers;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllersWithViews();

// Add DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Register SessionManager
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<SessionManager>();

// Add Session
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(1);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Name = ".AceJobAgency.Session";
});

// Add Email Service
builder.Services.AddScoped<EmailService>();

// Add HttpClient for ReCaptcha
builder.Services.AddHttpClient();

// Add Antiforgery token
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// Add security headers
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}
else
{
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

// Custom error pages
app.UseStatusCodePagesWithReExecute("/Home/ErrorHandler/{0}");

app.UseRouting();

// Security headers middleware
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

    // Different CSP for development and production
    if (app.Environment.IsDevelopment())
    {
        // More permissive CSP for development (allows Browser Link and localhost connections)
        context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google.com https://www.gstatic.com https://cdn.jsdelivr.net http://localhost:* https://localhost:*; " +
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
        "img-src 'self' data:; " +
        "font-src 'self'; " +
        "frame-src https://www.google.com; " +
        "connect-src 'self' https://www.google.com https://cdn.jsdelivr.net http://localhost:* https://localhost:* wss://localhost:* ws://localhost:* wss: ws:;";
    }
    else
    { 
        // Stricter CSP for production
        context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com https://cdn.jsdelivr.net; " +
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
        "img-src 'self' data:; " +
        "font-src 'self'; " +
        "frame-src https://www.google.com https://recaptcha.google.com; " +
        "connect-src 'self' https://www.google.com https://cdn.jsdelivr.net wss: ws:;";
    }

    await next();
});

app.UseSession();

// Session validation middleware
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value?.ToLower() ?? "";

    // Define public paths more strictly
    bool isPublicPath = path == "/" ||
                        path.Contains("/account/login") ||
                        path.Contains("/account/register") ||
                        path.Contains("/account/verify2fa") ||
                        path.Contains("/account/forgotpassword") ||
                        path.Contains("/account/resetpassword") ||
                        path.Contains("/home/error") ||
                        path.StartsWith("/css") ||
                        path.StartsWith("/js") ||
                        path.StartsWith("/lib");

    // If it's a public path, skip the MemberId check entirely
    if (isPublicPath)
    {
        await next();
        return;
    }

    // For all other paths, check if MemberId exists
    var memberId = context.Session.GetInt32("MemberId");
    if (!memberId.HasValue)
    {
        // Only redirect to "expired" if they were actually trying to reach a private page
        context.Response.Redirect("/Account/Login?expired=true");
        return;
    }

    await next();
});

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}");

app.Run();