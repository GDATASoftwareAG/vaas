package de.gdata.vaas.authentication;

import java.util.concurrent.CompletableFuture;

public interface IAuthenticator {
    CompletableFuture<String> getToken();
}
