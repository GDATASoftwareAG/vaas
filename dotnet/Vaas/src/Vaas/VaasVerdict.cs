using System.Collections.Generic;

namespace Vaas.Messages;

public class VaasVerdict
{
    public VaasVerdict(VerdictResponse verdictResponse)
    {
        Sha256 = verdictResponse.Sha256 ?? "";
        Verdict = verdictResponse.Verdict;
        Detections = verdictResponse.Detections;
        LibMagic = verdictResponse.LibMagic;
    }

    public string Sha256 { get; init; }
    public Verdict Verdict { get; init; }
    public List<Detection> Detections { get; init; }
    public LibMagic LibMagic { get; init; }
}
