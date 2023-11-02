using System;

namespace Vaas.Test.Authentication;

public static class AuthenticationEnvironment
{
    public static Uri TokenUrl => new Uri(DotNetEnv.Env.GetString(
        "TOKEN_URL",
        "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"));

    public static string ClientId => DotNetEnv.Env.GetString("CLIENT_ID");
    public static string ClientSecret => DotNetEnv.Env.GetString("CLIENT_SECRET");
    public static string ClientIdForResourceOwnerPasswordGrant => DotNetEnv.Env.GetString("VAAS_CLIENT_ID");
    public static string UserName => DotNetEnv.Env.GetString("VAAS_USER_NAME");
    public static string Password => DotNetEnv.Env.GetString("VAAS_PASSWORD");
}
