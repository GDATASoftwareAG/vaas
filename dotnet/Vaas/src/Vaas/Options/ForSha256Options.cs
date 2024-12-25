namespace Vaas.Options;

public class ForSha256Options
{
    public bool UseCache { get; init; } = true;
    public bool UseHashLookup { get; init; } = true;

    public string? VaasRequestId { get; init; }

    public static ForSha256Options From(VaasOptions options)
    {
        return new ForSha256Options
        {
            UseCache = options.UseCache,
            UseHashLookup = options.UseHashLookup,
            VaasRequestId = null,
        };
    }
}
