package de.gdata.vaas.authentication;

import java.io.IOException;

import de.gdata.vaas.exceptions.VaasAuthenticationException;

public interface IAuthenticator {
    /**
     * Get access token from identity provider
     * 
     * @throws IOException          if an I/O error occurs when sending the HTTP
     *                              request
     * @throws InterruptedException if the operation is interrupted
     * @return the access token
     * @throws VaasAuthenticationException 
     */
    public String getToken() throws IOException, InterruptedException, VaasAuthenticationException;
}
