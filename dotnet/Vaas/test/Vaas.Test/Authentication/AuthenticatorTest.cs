using System;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Moq;
using Moq.Contrib.HttpClient;
using Vaas.Authentication;
using Xunit;

namespace Vaas.Test.Authentication;

public class CountingDelegatingHandler : DelegatingHandler
{
    public int Requests { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Requests++;
        return await base.SendAsync(request, cancellationToken);
    }
}

public class AuthenticatorTest
{
    private readonly CountingDelegatingHandler _handler = new();
    private readonly Mock<ISystemClock> _systemClock = new();
    private readonly Authenticator _authenticator;

    public AuthenticatorTest()
    {
        DotNetEnv.Env.TraversePath().Load();
        _handler.InnerHandler = new HttpClientHandler();
        var httpClient = new HttpClient(_handler);
        _systemClock.Setup(x => x.UtcNow).Returns(() => DateTimeOffset.UtcNow);
        _authenticator = new Authenticator(httpClient, _systemClock.Object, GetVaasOptions());
    }

    [Fact]
    public async Task GetTokenAsync_IfTokenNotExpired_ReturnsLastToken()
    {
        _ = await _authenticator.GetTokenAsync(CancellationToken.None);
        _ = await _authenticator.GetTokenAsync(CancellationToken.None);
        Assert.Equal(1, _handler.Requests);
    }

    private VaasOptions GetVaasOptions() => new()
    {
        TokenUrl = AuthenticationEnvironment.TokenUrl,
        Credentials = new()
        {
            GrantType = GrantType.ClientCredentials,
            ClientId = AuthenticationEnvironment.ClientId,
            ClientSecret = AuthenticationEnvironment.ClientSecret
        }
    };

    [Fact]
    public async Task GetTokenAsync_IfTokenExpired_RefreshesToken()
    {
        _ = await _authenticator.GetTokenAsync(CancellationToken.None);
        _systemClock.Setup(x => x.UtcNow).Returns(() => DateTimeOffset.UtcNow + TimeSpan.FromHours(1));
        _ = await _authenticator.GetTokenAsync(CancellationToken.None);
        Assert.Equal(2, _handler.Requests);
    }

    [Fact]
    public async Task GetTokenAsync_IfClockSkew_ReusesToken()
    {
        _systemClock.Setup(x => x.UtcNow).Returns(() => DateTimeOffset.UtcNow + TimeSpan.FromHours(1));
        _ = await _authenticator.GetTokenAsync(CancellationToken.None);
        _ = await _authenticator.GetTokenAsync(CancellationToken.None);
        Assert.Equal(1, _handler.Requests);
    }

    [Fact]
    public async Task GetTokenAsync_IfNoExpiresIn_ThrowsAuthenticationException()
    {
        var handlerMock = UseHttpMessageHandlerMock();
        handlerMock.SetupRequest(HttpMethod.Post, GetVaasOptions().TokenUrl)
            .ReturnsResponse("""{"access_token": "My great token"}""");

        var e = await Assert.ThrowsAsync<AuthenticationException>(() => _authenticator.GetTokenAsync(CancellationToken.None));
        
        e.Message.Should().Be("Identity provider did not return expires_in.");
    }

    private Mock<HttpMessageHandler> UseHttpMessageHandlerMock()
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        _handler.InnerHandler = handlerMock.Object;
        return handlerMock;
    }
}