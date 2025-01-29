package de.gdata.vaas.exceptions;

/**
 * The Vaas authentication failed.
 * Recommended actions:
 * * Check the clientId and clientSecret passed to ClientCredentialsGrantAuthenticator.
 * * Make sure the token has not expired.
 */
public class VaasAuthenticationException extends Exception {
    public VaasAuthenticationException(String message, Throwable cause) {
        super(message != null ? message : "Authentication error", cause);
    }

    public VaasAuthenticationException(String message) {
        this(message, null);
    }

    public VaasAuthenticationException() {
        this(null, null);
    }
}
