package de.gdata.vaas.exceptions;

/**
 * The request is malformed or cannot be completed.
 * Recommended actions:
 * * Don't repeat the request.
 * * Log.
 * * Analyze the error.
 */
public class VaasClientException extends Exception {
    public VaasClientException(String message) {
        super(message != null ? message : "Client error");
    }
}
