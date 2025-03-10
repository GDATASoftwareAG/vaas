namespace Vaas.Options;

public class ForFileOptions
{
    public bool UseCache { get; init; } = true;
    public bool UseHashLookup { get; init; } = true;
    public string? VaasRequestId { get; init; }

    public static ForFileOptions From(VaasOptions options)
    {
        return new ForFileOptions
        {
            UseCache = options.UseCache,
            UseHashLookup = options.UseHashLookup,
            VaasRequestId = null,
        };
    }
}
