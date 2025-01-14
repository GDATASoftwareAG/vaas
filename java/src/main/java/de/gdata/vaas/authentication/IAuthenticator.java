package de.gdata.vaas.authentication;

import java.io.IOException;

import de.gdata.vaas.exceptions.VaasAuthenticationException;

public interface IAuthenticator {
    public String getToken() throws IOException, InterruptedException, VaasAuthenticationException;
}
