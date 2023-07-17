package de.gdata.vaas.exceptions;

/**
 * An invalid state was reached. Currently, this is only "connect() was not called".
 * Recommended actions:
 * * Check your code. Make sure that call connect() before sending any requests.
 */
public class VaasInvalidStateException extends Exception {
    public VaasInvalidStateException(String reason) {
        super(reason);
    }
}
