using System.Text.Json;
using Vaas.Messages;

namespace Vaas;

public class VaasVerdict
{
    public required string Sha256 { get; init; }
    public Verdict Verdict { get; init; }
    public string? Detection { get; init; }
    public string? MimeType { get; init; }
    public string? FileType { get; init; }

    public static VaasVerdict From(FileReport fileReport)
    {
        return new VaasVerdict
        {
            Sha256 = fileReport.Sha256,
            Verdict = fileReport.Verdict,
            Detection = fileReport.Detection,
            MimeType = fileReport.MimeType,
            FileType = fileReport.FileType,
        };
    }

    public static VaasVerdict From(UrlReport urlReport)
    {
        return new VaasVerdict
        {
            Sha256 = urlReport.Sha256,
            Verdict = urlReport.Verdict,
            Detection = urlReport.Detection,
            MimeType = urlReport.MimeType,
            FileType = urlReport.FileType,
        };
    }

    public override string ToString() => JsonSerializer.Serialize(this);
}
