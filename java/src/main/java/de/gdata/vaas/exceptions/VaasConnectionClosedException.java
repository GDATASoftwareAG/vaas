package de.gdata.vaas.exceptions;

/**
 * The connection to Vaas was closed.
 * Recommended actions:
 * * Call Vaas.connect() to reconnect
 */
public class VaasConnectionClosedException extends Exception {
    public VaasConnectionClosedException() {
        super("Connection was closed");
    }
}
