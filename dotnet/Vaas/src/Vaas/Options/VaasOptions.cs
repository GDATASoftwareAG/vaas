using System;

namespace Vaas.Options;

public class VaasOptions
{
    public bool UseHashLookup { get; init; } = true;
    public bool UseCache { get; init; } = true;

    public Uri VaasUrl { get; init; } = new("https://gateway.production.vaas.gdatasecurity.de");

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(300);
}
