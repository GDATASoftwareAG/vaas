using System;

namespace Vaas;

public class VaasInvalidStateException : Exception
{
    public VaasInvalidStateException() : base("Connect() was not called")
    {
    }
}

public class VaasAuthenticationException : Exception
{
    public VaasAuthenticationException() : base("Authentication failed")
    {
    }
}

public class VaasConnectionClosedException : Exception
{
    public VaasConnectionClosedException() : base("Connection closed")
    {
    }
}

public class VaasClientException : Exception 
{
    public VaasClientException(string? message) : base(message)
    {
    }
}

public class VaasServerException : Exception
{
    public VaasServerException(string? message) : base(message)
    {
    }
}
