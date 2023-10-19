using System;

namespace Vaas;

public class VaasOptions
{
    public Uri Url { get; set; } = new("https://upload.production.vaas.gdatasecurity.de");
    public bool? UseHashLookup { get; init; } = null;
    public bool? UseCache { get; init; } = null;

    public static readonly VaasOptions Defaults = new();
}