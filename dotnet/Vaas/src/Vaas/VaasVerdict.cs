namespace Vaas.Messages;

public class VaasVerdict
{
    public string Sha256 { get; init; }
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


    public static VaasVerdict From(VerdictResponse verdictResponse)
    {
        return new VaasVerdict
        {
            Sha256 = verdictResponse.Sha256 ?? "",
            Verdict = verdictResponse.Verdict,
            Detection = verdictResponse.Detection,
            MimeType = verdictResponse.MimeType,
            FileType = verdictResponse.FileType,
        };
    }
}