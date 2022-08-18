using System.Text.Json;
using Snapshooter.Xunit;
using Vaas.Messages;
using Xunit;

namespace Vaas.Test.Messages;

public class VerdictRequestTest
{
    [Fact]
    public void Serialize()
    {
        var json = JsonSerializer.Serialize(new VerdictRequest("", ""));
        Snapshot.Match(json);
    }
    
    [Fact]
    public void Serialize_WithOptions()
    {
        var json = JsonSerializer.Serialize(new VerdictRequest("", "") { UseCache = false, UseShed = false });
        Snapshot.Match(json);
    }
}