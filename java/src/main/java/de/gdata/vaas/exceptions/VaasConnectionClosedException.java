package de.gdata.vaas.exceptions;

public class VaasConnectionClosedException extends Exception {

    public VaasConnectionClosedException() {
        super("Connection was closed");
    }
}
