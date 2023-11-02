using System;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Snapshooter.Xunit;
using Xunit;

namespace Vaas.Test;

public class VaasOptionsTest
{
    [Fact]
    public void Value_ForPassword_ReturnsOptions()
    {
        var provider = GetServices(new()
        {
            { "TokenUrl", "https://account-staging.gdata.de/realms/vaas-staging/protocol/openid-connect/token" },
            { "Credentials:GrantType", "Password" },
            { "Credentials:ClientId", "clientId" },
            { "Credentials:UserName", "userName" },
            { "Credentials:Password", "password" },
        });
        
        var options = provider.GetRequiredService<IOptions<VaasOptions>>().Value;

        options.MatchSnapshot();
    }

    [Fact]
    public void Value_ForClientCredentials_ReturnsOptions()
    {
        var provider = GetServices(new()
        {
            { "Credentials:GrantType", "ClientCredentials" },
            { "Credentials:ClientId", "clientId" },
            { "Credentials:ClientSecret", "clientSecret" },
        });

        var options = provider.GetRequiredService<IOptions<VaasOptions>>().Value;

        options.MatchSnapshot();
    }
    
    [Fact]
    public void Value_IfFieldsAreMissing_ThrowsOptionsValidationException()
    {
        var provider = GetServices(new());

        // Exception is thrown, when Value is called
        var e = Assert.Throws<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptions<VaasOptions>>().Value);

        Assert.Equal(
            "DataAnnotation validation failed for 'VaasOptions' members: 'Credentials' with the error: 'The Credentials field is required.'.",
            e.Message);
    }
    
    [Fact]
    public void Value_IfClientCredentialsAndSecretIsMissing_ThrowsOptionsValidationException()
    {
        var provider = GetServices(new()
        {
            { "Credentials:GrantType", "ClientCredentials" },
            { "Credentials:ClientId", "ClientId" }
        });

        // Exception is thrown, when Value is called
        var e = Assert.Throws<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptions<VaasOptions>>().Value);

        Assert.Equal(
            "DataAnnotation validation failed for 'VaasOptions' members: 'Credentials' with the error: 'The fields ClientId and ClientSecret are required for the GrantType ClientCredentials.'.",
            e.Message);
    }

    [Fact]
    public void Value_IfPasswordAndUserNameIsMissing_ThrowsOptionsValidationException()
    {
        var provider = GetServices(new()
        {
            { "Credentials:GrantType", "Password" },
            { "Credentials:ClientId", "ClientId" }
        });

        // Exception is thrown, when Value is called
        var e = Assert.Throws<OptionsValidationException>(() =>
            provider.GetRequiredService<IOptions<VaasOptions>>().Value);

        Assert.Equal(
            "DataAnnotation validation failed for 'VaasOptions' members: 'Credentials' with the error: 'The fields ClientId, UserName and Password are required for the GrantType Password.'.",
            e.Message);
    }
    
    private static IServiceProvider GetServices(Dictionary<string, string> data)
    {
        var s = new MemoryConfigurationSource() { InitialData = data };
        var configuration = new ConfigurationBuilder()
            .Add(s)
            .Build();

        var services = new ServiceCollection();
        services
            .AddOptions<VaasOptions>()
            .Bind(configuration)
            .ValidateDataAnnotations();
        return services.BuildServiceProvider();
    }
}