public class RegisterModel
{
    public required string Email { get; set; }
    public required string Password { get; set; }
    public required string FirstName { get; set; }
    public required string LastName { get; set; }
    public required string Country { get; set; }
    public required string Bio { get; set; }
    public required string BioTitle { get; set; }
}

public class LoginModel
{
    public required string Email { get; set; }
    public required string Password { get; set; }
}
