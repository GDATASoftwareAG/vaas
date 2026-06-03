using Vaas.Messages;
using Xunit;

namespace Vaas.Test;

public class VaasVerdictTest
{
    [Fact]
    public void VaasVerdict_FromFileReport_PreservesIsEncrypted()
    {
        var fileReport = new FileReport
        {
            Sha256 = VaasTest.EncryptedSha256,
            Verdict = Verdict.Clean,
            IsEncrypted = true,
        };

        Assert.True(VaasVerdict.From(fileReport).IsEncrypted);
    }

    [Fact]
    public void VaasVerdict_FromUrlReport_PreservesIsEncrypted()
    {
        var urlReport = new UrlReport
        {
            Sha256 = VaasTest.EicarInEncryptedSha256,
            Verdict = Verdict.Malicious,
            Url = VaasTest.WithAndWithoutPasswordUrl,
            IsEncrypted = true,
        };

        Assert.True(VaasVerdict.From(urlReport).IsEncrypted);
    }
}
