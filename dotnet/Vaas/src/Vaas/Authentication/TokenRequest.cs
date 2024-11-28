using System;
using System.ComponentModel.DataAnnotations;
using CommunityToolkit.Diagnostics;

namespace Vaas.Authentication;

public enum GrantType
{
    ClientCredentials,
    Password,
}

public class TokenRequest
{
    [Required]
    public GrantType GrantType { get; set; }

    [Required]
    public string ClientId { get; set; } = string.Empty;
    public string? ClientSecret { get; set; }

    public string? UserName { get; set; }
    public string? Password { get; set; }

    public static ValidationResult IsValid(TokenRequest? request, ValidationContext context)
    {
        Guard.IsNotNull(request);
        var memberNames = new[] { context.MemberName ?? "" };
        if (request.GrantType == GrantType.ClientCredentials)
        {
            if (
                string.IsNullOrWhiteSpace(request.ClientId)
                || string.IsNullOrWhiteSpace(request.ClientSecret)
            )
            {
                return new ValidationResult(
                    "The fields ClientId and ClientSecret are required for the GrantType ClientCredentials.",
                    memberNames
                );
            }

            return ValidationResult.Success!;
        }

        if (request.GrantType == GrantType.Password)
        {
            if (
                string.IsNullOrWhiteSpace(request.ClientId)
                || string.IsNullOrWhiteSpace(request.UserName)
                || string.IsNullOrWhiteSpace(request.Password)
            )
            {
                return new ValidationResult(
                    "The fields ClientId, UserName and Password are required for the GrantType Password.",
                    memberNames
                );
            }

            return ValidationResult.Success!;
        }

        throw new ArgumentOutOfRangeException();
    }
}
