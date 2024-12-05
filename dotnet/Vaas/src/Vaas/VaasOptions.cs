using System;
using System.ComponentModel.DataAnnotations;
using Vaas.Authentication;

namespace Vaas;

public class VaasOptions
{
    public Uri Url { get; set; } = new("https://upload.production.vaas.gdatasecurity.de");
    public bool? UseHashLookup { get; init; } = null;
    public bool? UseCache { get; init; } = null;

    public Uri TokenUrl { get; set; } =
        new Uri("https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token");

    [Required]
    [CustomValidation(typeof(TokenRequest), nameof(TokenRequest.IsValid))]
    public TokenRequest Credentials { get; set; } = null!;
}
