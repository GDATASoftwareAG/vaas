namespace Vaas.Messages;

public class VaasVerdict
{
    public VaasVerdict(VerdictResponse verdictResponse)
    {
        Sha256 = verdictResponse.Sha256 ?? "";
        Verdict = verdictResponse.Verdict;
    }

    public string Sha256 { get; init; }
    public Verdict Verdict { get; init; }
}
