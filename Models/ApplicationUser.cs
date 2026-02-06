using Microsoft.AspNetCore.Identity;

namespace appsec_assignment_2.Models;

public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Gender { get; set; } = string.Empty;
    public string EncryptedNRIC { get; set; } = string.Empty;
    public DateTime DateOfBirth { get; set; }
    public string? ResumePath { get; set; }
    public string WhoAmI { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastPasswordChangeDate { get; set; }
    public string? CurrentSessionId { get; set; }
    public bool MustChangePassword { get; set; } = false;
}
