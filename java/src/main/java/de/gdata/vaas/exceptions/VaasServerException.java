package de.gdata.vaas.exceptions;

/**
 * The server encountered an internal error.
 * Recommended actions:
 * * You may retry the request after a certain delay.
 * * If the problem persists contact G DATA.
 */
public class VaasServerException extends Exception {
    public VaasServerException(String message, Exception cause) {
        super(message != null ? message : "Server error", cause);
    }

    public VaasServerException(String message) {
        this(message, null);
    }

    public VaasServerException() {
        this(null, null);
    }
}
