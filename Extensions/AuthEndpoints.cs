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
        var authGroup = app.MapGroup("/api/auth");

        // Register endpoint
        authGroup.MapPost("/register", Register);

        // Login endpoint
        authGroup.MapPost("/login", Login);
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

        return Results.Ok("User registered successfully with role " + role);
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
}