using System;
using System.Diagnostics;
using System.Net;
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

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    )
    {
        Requests++;
        return await base.SendAsync(request, cancellationToken);
    }
}

public class AuthenticatorTest
{
    private readonly CountingDelegatingHandler _handler = new();
    private readonly Mock<ISystemClock> _systemClock = new();
    private readonly HttpClient _httpClient;
    private readonly ClientCredentialsGrantAuthenticator _authenticator;

    public AuthenticatorTest()
    {
        DotNetEnv.Env.TraversePath().Load();
        _handler.InnerHandler = new HttpClientHandler();
        _httpClient = new HttpClient(_handler);
        _systemClock.Setup(x => x.UtcNow).Returns(() => DateTimeOffset.UtcNow);
        _authenticator = GetClientCredentialsGrantAuthenticator();
    }

    private ClientCredentialsGrantAuthenticator GetClientCredentialsGrantAuthenticator()
    {
        return new ClientCredentialsGrantAuthenticator(
            AuthenticationEnvironment.ClientId,
            AuthenticationEnvironment.ClientSecret,
            AuthenticationEnvironment.TokenUrl,
            _httpClient,
            _systemClock.Object
        );
    }

    private ResourceOwnerPasswordGrantAuthenticator GetResourceOwnerPasswordGrantAuthenticator()
    {
        return new ResourceOwnerPasswordGrantAuthenticator(
            AuthenticationEnvironment.ClientIdForResourceOwnerPasswordGrant,
            AuthenticationEnvironment.UserName,
            AuthenticationEnvironment.Password,
            AuthenticationEnvironment.TokenUrl,
            _httpClient,
            _systemClock.Object
        );
    }

    [Fact]
    public async Task GetTokenAsync_WithClientCredentials_ReturnsToken()
    {
        var authenticator = GetClientCredentialsGrantAuthenticator();

        _ = await authenticator.GetTokenAsync(CancellationToken.None);

        Assert.Equal(1, _handler.Requests);
    }

    [Fact]
    public async Task GetTokenAsync_WithPassword_ReturnsToken()
    {
        var authenticator = GetResourceOwnerPasswordGrantAuthenticator();

        _ = await authenticator.GetTokenAsync(CancellationToken.None);

        Assert.Equal(1, _handler.Requests);
    }

    [Fact]
    public async Task GetTokenAsync_IfTokenNotExpired_ReturnsLastToken()
    {
        _ = await _authenticator.GetTokenAsync(CancellationToken.None);
        _ = await _authenticator.GetTokenAsync(CancellationToken.None);

        Assert.Equal(1, _handler.Requests);
    }

    [Fact]
    public async Task GetTokenAsync_IfTokenExpired_GetsNewToken()
    {
        _ = await _authenticator.GetTokenAsync(CancellationToken.None);
        _systemClock
            .Setup(x => x.UtcNow)
            .Returns(() => DateTimeOffset.UtcNow + TimeSpan.FromHours(1));

        _ = await _authenticator.GetTokenAsync(CancellationToken.None);

        Assert.Equal(2, _handler.Requests);
    }

    [Fact]
    public async Task GetTokenAsync_IfClockSkew_ReusesToken()
    {
        _systemClock
            .Setup(x => x.UtcNow)
            .Returns(() => DateTimeOffset.UtcNow + TimeSpan.FromHours(1));
        _ = await _authenticator.GetTokenAsync(CancellationToken.None);
        _ = await _authenticator.GetTokenAsync(CancellationToken.None);
        Assert.Equal(1, _handler.Requests);
    }

    [Fact]
    public async Task GetTokenAsync_IfNoExpiresIn_ThrowsAuthenticationException()
    {
        var handlerMock = UseHttpMessageHandlerMock();
        handlerMock
            .SetupRequest(HttpMethod.Post, AuthenticationEnvironment.TokenUrl)
            .ReturnsResponse("""{"access_token": "My great token"}""");

        var e = await Assert.ThrowsAsync<AuthenticationException>(
            () => _authenticator.GetTokenAsync(CancellationToken.None)
        );

        e.Message.Should().Be("Identity provider did not return expires_in");
    }

    [Fact]
    public async Task GetTokenAsync_IfUnauthorized_ThrowsAuthenticationException()
    {
        var handlerMock = UseHttpMessageHandlerMock();
        MockUnauthorizedClient(handlerMock);

        var e = await Assert.ThrowsAsync<AuthenticationException>(
            () => _authenticator.GetTokenAsync(CancellationToken.None)
        );

        e.Message.Should()
            .Be(
                "Identity provider returned status code 401: Invalid client or Invalid client credentials"
            );
    }

    private static void MockUnauthorizedClient(Mock<HttpMessageHandler> handlerMock)
    {
        handlerMock
            .SetupRequest(HttpMethod.Post, AuthenticationEnvironment.TokenUrl)
            .ReturnsResponse(
                """{"error":"unauthorized_client","error_description":"Invalid client or Invalid client credentials"}""",
                configure: response =>
                {
                    response.StatusCode = HttpStatusCode.Unauthorized;
                }
            );
    }

    [Fact]
    public async Task GetTokenAsync_IfHttpError_ThrowsAuthenticationException()
    {
        var handlerMock = UseHttpMessageHandlerMock();
        handlerMock
            .SetupRequest(HttpMethod.Post, AuthenticationEnvironment.TokenUrl)
            .ReturnsResponse(HttpStatusCode.InternalServerError);

        var e = await Assert.ThrowsAsync<AuthenticationException>(
            () => _authenticator.GetTokenAsync(CancellationToken.None)
        );

        e.Message.Should()
            .Be(
                "Identity provider returned status code 500: The input does not contain any JSON tokens. Expected the input to start with a valid JSON token, when isFinalBlock is true. Path: $ | LineNumber: 0 | BytePositionInLine: 0."
            );
    }

    [Fact]
    public async Task GetTokenAsync_IfHttpRequestException_ThrowsAuthenticationException()
    {
        var handlerMock = UseHttpMessageHandlerMock();
        handlerMock
            .SetupRequest(HttpMethod.Post, AuthenticationEnvironment.TokenUrl)
            .Throws(
                new HttpRequestException(
                    "Name or service not known (dsdkfsdufsdufoweuiruierlknclxoijfiowejf.de:80)"
                )
            );

        var e = await Assert.ThrowsAsync<AuthenticationException>(
            () => _authenticator.GetTokenAsync(CancellationToken.None)
        );
        e.Message.Should().Be("Failed to request token");
        e.InnerException.Should().BeOfType<HttpRequestException>();
        e.InnerException!.Message.Should()
            .Be("Name or service not known (dsdkfsdufsdufoweuiruierlknclxoijfiowejf.de:80)");
    }

    private Mock<HttpMessageHandler> UseHttpMessageHandlerMock()
    {
        var handlerMock = new Mock<HttpMessageHandler>();
        _handler.InnerHandler = handlerMock.Object;
        return handlerMock;
    }

    [Fact]
    public async Task GetTokenAsync_IfLastRequestFailed_Waits1sBeforeNextRequest()
    {
        var handlerMock = UseHttpMessageHandlerMock();
        MockUnauthorizedClient(handlerMock);
        var staticNow = DateTimeOffset.UtcNow;
        _systemClock.Setup(x => x.UtcNow).Returns(() => staticNow);

        await Assert.ThrowsAsync<AuthenticationException>(
            () => _authenticator.GetTokenAsync(CancellationToken.None)
        );
        var sw = Stopwatch.StartNew();
        await Assert.ThrowsAsync<AuthenticationException>(
            () => _authenticator.GetTokenAsync(CancellationToken.None)
        );
        sw.Elapsed.Should().BeGreaterOrEqualTo(TimeSpan.FromSeconds(1));
    }
}
