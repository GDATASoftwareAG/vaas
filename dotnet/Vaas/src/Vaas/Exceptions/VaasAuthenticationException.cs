using System;

namespace Vaas.Exceptions;

public class VaasAuthenticationException : Exception
{
    public VaasAuthenticationException()
        : base("Authentication failed") { }

    public VaasAuthenticationException(string message)
        : base(message) { }
}
