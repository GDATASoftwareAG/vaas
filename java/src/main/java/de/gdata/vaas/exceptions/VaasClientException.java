package de.gdata.vaas.exceptions;

/**
 * The request is malformed or cannot be completed.
 * Recommended actions:
 * * Don't repeat the request.
 * * Log.
 * * Analyze the error.
 */
public class VaasClientException extends Exception {
    public VaasClientException(String message, Exception cause) {
        super(message != null ? message : "Client error", cause);
    }

    public VaasClientException(String message) {
        this(message, null);
    }

    public VaasClientException() {
        this(null, null);
    }
}
