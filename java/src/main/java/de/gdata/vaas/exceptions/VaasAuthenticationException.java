package de.gdata.vaas.exceptions;

/**
 * The Vaas authentication failed.
 * Recommended actions:
 * * Check the clientId and clientSecret passed to ClientCredentialsGrantAuthenticator.
 * * Make sure the token has not expired.
 */
public class VaasAuthenticationException extends Exception {

    public VaasAuthenticationException() {
        super("Vaas authentication failed");
    }
}
