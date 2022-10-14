package de.gdata.vaas;

import java.io.IOException;
import java.net.URISyntaxException;

public interface IClientCredentialsGrantAuthenticator {
    public String getToken() throws URISyntaxException, IOException, InterruptedException;
}
