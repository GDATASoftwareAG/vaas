using System;
using System.Text.Json;
using Vaas.Messages;
using Xunit;

namespace Vaas.Test;

public class TokenResponseTest
{
    [Fact]
    public void Deserialize_IfFieldIsMissing_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => JsonSerializer.Deserialize<TokenResponse>("{}"));
    }
}