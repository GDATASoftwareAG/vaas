package de.gdata.vaas.authentication;

import de.gdata.vaas.exceptions.VaasAuthenticationException;

import java.util.concurrent.CompletableFuture;

public interface IAuthenticator {
    CompletableFuture<String> getToken() throws VaasAuthenticationException;
}
