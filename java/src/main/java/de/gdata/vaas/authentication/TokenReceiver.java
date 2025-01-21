package de.gdata.vaas.authentication;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import de.gdata.vaas.exceptions.VaasAuthenticationException;
import lombok.NonNull;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

abstract class TokenReceiver {
    private final Lock lock = new ReentrantLock();

    @NonNull
    private final URI tokenUrl;
    @NonNull
    private final HttpClient httpClient;
    private TokenResponse lastTokenResponse = null;
    private Instant validTo = Instant.EPOCH;
    private Instant lastRequestTime = null;

    public TokenReceiver(@NotNull URI tokenUrl, @NotNull HttpClient httpClient) {
        this.tokenUrl = tokenUrl;
        this.httpClient = httpClient;
    }

    public TokenReceiver(@NotNull URI tokenUrl) {
        this(tokenUrl, HttpClient.newHttpClient());
    }

    public TokenReceiver() throws URISyntaxException {
        this(new URI("https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"), HttpClient.newHttpClient());
    }

    public String getToken() throws VaasAuthenticationException {
        lock.lock();
        try {
            Instant now = Instant.now();
            if (lastTokenResponse != null && validTo.isAfter(now)) {
                return lastTokenResponse.accessToken();
            }

            if (lastRequestTime != null) {
                long timeToWait = lastRequestTime.plusSeconds(1).getEpochSecond() - now.getEpochSecond();
                if (timeToWait > 0) {
                    Thread.sleep(timeToWait * 1000);
                }
            }

            lastRequestTime = Instant.now();
            lastTokenResponse = requestToken();
            validTo = Instant.now().plusSeconds(lastTokenResponse.expiresInSeconds());
            return lastTokenResponse.accessToken();
        } catch (Exception ex) {
            throw new VaasAuthenticationException("Failed to get token");
        } finally {
            lock.unlock();
        }
    }

    private TokenResponse requestToken() throws VaasAuthenticationException {
        try {
            String form = tokenRequestToForm();
            HttpRequest request = HttpRequest.newBuilder(tokenUrl)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                JsonObject errorResponse = JsonParser.parseString(response.body()).getAsJsonObject();
                throw new VaasAuthenticationException("Identity provider returned status code " + response.statusCode() + ": " + errorResponse.get("error_description").getAsString());
            }

            JsonObject tokenResponse = JsonParser.parseString(response.body()).getAsJsonObject();
            String accessToken = tokenResponse.get("access_token").getAsString();
            int expiresIn = tokenResponse.get("expires_in").getAsInt();

            return new TokenResponse(accessToken, expiresIn);
        } catch (IOException | InterruptedException ex) {
            throw new VaasAuthenticationException("Failed to request token", ex);
        }
    }

    protected abstract String tokenRequestToForm();
}