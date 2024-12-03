using System;

namespace Vaas;

public class VaasInvalidStateException : Exception
{
    public VaasInvalidStateException()
        : base("Connect() was not called") { }
}

public class VaasAuthenticationException : Exception
{
    public VaasAuthenticationException()
        : base("Authentication failed") { }
    public VaasAuthenticationException(string message)
        : base(message) { }

}

public class VaasConnectionClosedException : Exception
{
    public VaasConnectionClosedException()
        : base("Connection closed") { }
}

/// <summary>The request is malformed or cannot be completed.</summary>
/// <remarks>
/// Recommended actions:
/// <ul>
///   <li>Don't repeat the request.</li>
///   <li>Log.</li>
///   <li>Analyze the error</li>
/// </ul>
/// </remarks>
public class VaasClientException : Exception
{
    public VaasClientException(string? message)
        : base(message) { }

    public VaasClientException(string? message, Exception? innerException)
        : base(message, innerException) { }
}

/// <summary>The server encountered an internal error.</summary>
/// <remarks>
/// Recommended actions:
/// <ul>
///   <li>You may retry the request after a certain delay.</li>
///   <li>If the problem persists contact G DATA.</li>
/// </ul>
/// </remarks>
public class VaasServerException : Exception
{
    public VaasServerException(string? message)
        : base(message) { }

    public VaasServerException(string? message, Exception? innerException)
        : base(message, innerException) { }
}
