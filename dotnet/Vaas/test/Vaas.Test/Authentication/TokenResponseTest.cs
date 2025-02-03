using System;
using System.Text.Json;
using Vaas.Authentication;
using Xunit;

namespace Vaas.Test.Authentication;

public class TokenResponseTest
{
    [Fact]
    public void Deserialize_IfFieldIsMissing_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JsonSerializer.Deserialize<TokenResponse>("{}"));
    }
}
