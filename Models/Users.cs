using Microsoft.AspNetCore.Identity;

public class Users : IdentityUser
{
    public required string FirstName { get; set; }
    public required string LastName { get; set; }
    public required string Country { get; set; }
    public required string Bio { get; set; }
    public required string BioTitle { get; set; }
}