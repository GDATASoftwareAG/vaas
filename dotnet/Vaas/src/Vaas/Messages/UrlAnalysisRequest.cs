using System;

namespace Vaas.Messages;

public class UrlAnalysisRequest
{
    public required Uri Url { get; set; }
    public bool? UseHashLookup { get; set; } = true;
}
