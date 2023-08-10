package de.gdata.vaas.exceptions;

/**
 * The server encountered an internal error.
 * Recommended actions:
 * * You may retry the request after a certain delay.
 * * If the problem persists contact G DATA.
 */
public class VaasServerException extends Exception {
    public VaasServerException(String message) {
        super(message != null ? message : "Server error");
    }
}
