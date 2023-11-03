using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Vaas.Authentication;

namespace Vaas;

public static class ServiceCollectionExtensions
{
    private const string SectionKey = "VerdictAsAService";
    
    public static IServiceCollection AddVerdictAsAService(this IServiceCollection services, IConfiguration configuration)
    {
        var configurationSection = configuration.GetSection(SectionKey);
        services
            .AddOptions<VaasOptions>()
            .Bind(configurationSection)
            .ValidateDataAnnotations();
        
        services
            .AddSingleton<VaasOptions>(p => p.GetRequiredService<IOptions<VaasOptions>>().Value)
            .AddSingleton<IAuthenticator, Authenticator>();
    
        services
            .AddTransient<BearerTokenHandler>()
            .AddHttpClient<IVaas, Vaas>()
            .AddHttpMessageHandler<BearerTokenHandler>();

        return services;
    }
}
