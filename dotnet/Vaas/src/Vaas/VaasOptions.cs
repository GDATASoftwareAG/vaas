namespace Vaas;

public class VaasOptions
{
    public bool? UseShed { get; init; } = null;
    public bool? UseCache { get; init; } = null;

    public static VaasOptions Defaults = new();
}