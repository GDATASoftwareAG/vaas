package de.gdata.vaas.authentication;

import de.gdata.vaas.exceptions.VaasAuthenticationException;

public interface IAuthenticator {
    String getToken() throws VaasAuthenticationException;
}
