namespace Vaas.Messages;

public class FileAnalysisStarted
{
    public required ChecksumSha256 Sha256 { get; init; }
}