namespace Vaas.Options;

public class ForUrlOptions
{
    public bool UseHashLookup { get; init; } = true;
    public string? VaasRequestId { get; init; }

    public static ForUrlOptions From(VaasOptions options)
    {
        return new ForUrlOptions { UseHashLookup = options.UseHashLookup, VaasRequestId = null };
    }
}
