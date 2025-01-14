namespace Vaas.Options;

public class ForStreamOptions
{
    public bool UseHashLookup { get; init; } = true;
    public string? VaasRequestId { get; init; }

    public static ForStreamOptions From(VaasOptions options)
    {
        return new ForStreamOptions { UseHashLookup = options.UseHashLookup, VaasRequestId = null };
    }
}
