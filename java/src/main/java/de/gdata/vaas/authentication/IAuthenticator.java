package de.gdata.vaas.authentication;

import de.gdata.vaas.exceptions.VaasAuthenticationException;

import java.io.IOException;

public interface IAuthenticator {
    String getToken() throws IOException, InterruptedException, VaasAuthenticationException;
}
