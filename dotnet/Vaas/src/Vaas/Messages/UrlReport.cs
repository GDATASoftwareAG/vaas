using System;

namespace Vaas.Messages;

public class UrlReport
{
    public required ChecksumSha256 Sha256 { get; init; }
    public required Verdict Verdict { get; init; }
    public required Uri Url { get; set; }
    public string? Detection { get; init; }
    public string? FileType { get; init; }
    public string? MimeType { get; init; }
}
