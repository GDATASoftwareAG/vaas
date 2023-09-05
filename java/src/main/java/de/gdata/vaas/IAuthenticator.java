package de.gdata.vaas;

import java.io.IOException;

public interface IAuthenticator {
    /**
     * Get access token from identity provider
     * 
     * @throws IOException          if an I/O error occurs when sending the HTTP
     *                              request
     * @throws InterruptedException if the operation is interrupted
     * @return the access token
     */
    public String getToken() throws IOException, InterruptedException;
}
