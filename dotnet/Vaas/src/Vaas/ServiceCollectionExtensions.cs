using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Vaas.Authentication;
using Vaas.Options;

namespace Vaas;

public static class ServiceCollectionExtensions
{
    private const string SectionKey = "VerdictAsAService";

    public static IServiceCollection AddVerdictAsAService(
        this IServiceCollection services,
        IConfiguration configuration
    )
    {
        var configurationSection = configuration.GetSection(SectionKey);

        var optionsSection = configurationSection.GetSection("Options");
        var vaasOptions = new VaasOptions
        {
            UseHashLookup = optionsSection.GetValue<bool>("UseHashLookup"),
            UseCache = optionsSection.GetValue<bool>("UseCache"),
            VaasUrl =
                optionsSection.GetValue<Uri>("VaasUrl")
                ?? new Uri("https://gateway.production.vaas.gdatasecurity.de"),
            Timeout = TimeSpan.FromSeconds(optionsSection.GetValue<int>("Timeout")),
        };

        IAuthenticator authenticator;
        if (
            configurationSection.GetSection("Credentials").GetValue<string>("GrantType")
            == GrantType.ClientCredentials.ToString()
        )
        {
            authenticator = new ClientCredentialsGrantAuthenticator(
                configurationSection.GetSection("Credentials").GetValue<string>("ClientId")
                    ?? throw new ArgumentException(
                        "ClientId is required in VerdictAsAService configuration"
                    ),
                configurationSection.GetSection("Credentials").GetValue<string>("ClientSecret")
                    ?? throw new ArgumentException(
                        "ClientSecret is required in VerdictAsAService configuration"
                    ),
                configurationSection.GetSection("Credentials").GetValue<Uri>("TokenUrl")
            );
        }
        else if (
            configurationSection.GetSection("Credentials").GetValue<string>("GrantType")
            == GrantType.Password.ToString()
        )
        {
            authenticator = new ResourceOwnerPasswordGrantAuthenticator(
                configurationSection.GetSection("Credentials").GetValue<string>("ClientId")
                    ?? throw new ArgumentException(
                        "ClientId is required in VerdictAsAService configuration"
                    ),
                configurationSection.GetSection("Credentials").GetValue<string>("Username")
                    ?? throw new ArgumentException(
                        "UserName is required in VerdictAsAService configuration"
                    ),
                configurationSection.GetSection("Credentials").GetValue<string>("Password")
                    ?? throw new ArgumentException(
                        "Password is required in VerdictAsAService configuration"
                    ),
                configurationSection.GetSection("Credentials").GetValue<Uri>("TokenUrl")
            );
        }
        else
        {
            throw new ArgumentException("GrantType must be either ClientCredentials or Password");
        }

        services.AddSingleton(authenticator);
        services.AddSingleton(vaasOptions);
        services.AddHttpClient<IVaas, Vaas>();
        services.AddSingleton<IVaas, Vaas>();

        return services;
    }
}
