using System;

namespace Vaas.Messages;

public class UrlAnalysisRequest
{
    public Uri url { get; set; }
    public bool? useHashLookup { get; set; } = true;
}
