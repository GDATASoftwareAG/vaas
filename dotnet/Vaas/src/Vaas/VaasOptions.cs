namespace Vaas;

public class VaasOptions
{
    public bool? UseHashLookup { get; init; } = null;
    public bool? UseCache { get; init; } = null;

    public static readonly VaasOptions Defaults = new();
}