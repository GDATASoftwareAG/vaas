using System.Collections.Generic;

namespace Vaas.Messages;

public class VaasVerdict(VerdictResponse verdictResponse)
{
    public string Sha256 { get; init; } = verdictResponse.Sha256 ?? "";
    public Verdict Verdict { get; init; } = verdictResponse.Verdict;
    public string? Detection { get; init; } = verdictResponse.Detection;
    public string? MimeType { get; init; } = verdictResponse.FileType;
    public string? FileType { get; init; } = verdictResponse.MimeType;
}
