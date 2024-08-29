using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;


public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this WebApplication app)
    {
        // Grouping related endpoints under a common route prefix
        var authGroup = app.MapGroup("/api/auth").AllowAnonymous();

        // Register endpoint
        authGroup.MapPost("/register", Register).AllowAnonymous();

        // Login endpoint
        authGroup.MapPost("/login", Login).AllowAnonymous();
        // Upload avatar
        authGroup.MapPost("/photo", UploadAvatar).DisableAntiforgery()
               .AllowAnonymous();
    }

    private static async Task<IResult> Register(
        UserManager<Users> userManager,
        RoleManager<IdentityRole> roleManager,
        RegisterModel model)
    {
        var user = new Users
        {
            UserName = model.Email,
            Email = model.Email,
            FirstName = model.FirstName,
            LastName = model.LastName,
            Country = model.Country,
            Bio = model.Bio,
            BioTitle = model.BioTitle
        };

        var result = await userManager.CreateAsync(user, model.Password);
        if (!result.Succeeded)
        {
            return Results.BadRequest(result.Errors);
        }

        // Assign role to the user
        var role = model.Role ?? "Client"; // Default to "Client" if no role is provided
        if (!await roleManager.RoleExistsAsync(role))
        {
            return Results.BadRequest($"Role '{role}' does not exist.");
        }

        await userManager.AddToRoleAsync(user, role);

        // Return success message with the new user's ID
        return Results.Ok(new { Message = "User registered successfully with role " + role, UserId = user.Id });
    }

    private static async Task<IResult> Login(
        SignInManager<Users> signInManager,
        IConfiguration configuration, // Injecting IConfiguration
        LoginModel model)
    {
        var result = await signInManager.PasswordSignInAsync(model.Email, model.Password, false, lockoutOnFailure: false);
        if (result.Succeeded)
        {
            var user = await signInManager.UserManager.FindByEmailAsync(model.Email);
#pragma warning disable CS8604 // Possible null reference argument.
            var token = GenerateJwtToken(user, configuration);
#pragma warning restore CS8604 // Possible null reference argument.
            return Results.Ok(new { Token = token });
        }
        return Results.BadRequest("Invalid login attempt");
    }

    private static string GenerateJwtToken(Users user, IConfiguration configuration)
    {
#pragma warning disable CS8604 // Possible null reference argument.
        var claims = new[]
        {
        new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };
#pragma warning restore CS8604 // Possible null reference argument.

#pragma warning disable CS8604 // Possible null reference argument.
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]));
#pragma warning restore CS8604 // Possible null reference argument.
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: configuration["Jwt:Issuer"],
            audience: configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static async Task<IResult> UploadAvatar(IFormFile avatarFile, UserManager<Users> userManager,
    ApplicationDbContext dbContext,
    string userId) // Pass userId to identify the user
    {
        if (avatarFile == null || avatarFile.Length == 0)
        {
            return Results.BadRequest("No file uploaded.");
        }

        // Validate file type and size
        var allowedExtensions = new[] { ".jpg", ".jpeg", ".png" };
        var extension = Path.GetExtension(avatarFile.FileName).ToLowerInvariant();
        if (!allowedExtensions.Contains(extension))
        {
            return Results.BadRequest("Invalid file type. Only JPG, JPEG, and PNG files are allowed.");
        }

        if (avatarFile.Length > 4 * 1024 * 1024) // Limit file size to 2MB
        {
            return Results.BadRequest("File size exceeds the limit of 2MB.");
        }

        // Generate a unique file name to avoid conflicts
        var fileName = $"{Guid.NewGuid()}{extension}";
        var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "uploads");
        var filePath = Path.Combine(uploadsFolder, fileName);



        using (var stream = new FileStream(filePath, FileMode.Create))
        {
            await avatarFile.CopyToAsync(stream);
        }

        // Update user's avatar path in the database
        var user = await userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return Results.NotFound("User not found.");
        }

        user.PhotoUrl = $"/uploads/{fileName}";

        var result = await userManager.UpdateAsync(user);
        if (!result.Succeeded)   //If operation is failed delete uploaded file
        {
            // Handle update failure (rollback file creation, etc.)
            File.Delete(filePath);
            return Results.BadRequest(result.Errors);
        }

        // Save changes to the database
        await dbContext.SaveChangesAsync();


        return Results.Ok(new { FilePath = $"/uploads/{fileName}" });
    }

}