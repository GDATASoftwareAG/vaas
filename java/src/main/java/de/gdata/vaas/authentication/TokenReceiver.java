package de.gdata.vaas.authentication;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.ibm.asyncutil.locks.AsyncLock;
import de.gdata.vaas.exceptions.VaasAuthenticationException;
import lombok.NonNull;
import org.jetbrains.annotations.NotNull;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;

abstract class TokenReceiver {
    private final AsyncLock lock = AsyncLock.createFair();

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

    public TokenReceiver() {
        this(URI.create("https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token"),
                HttpClient.newHttpClient());
    }

    public CompletableFuture<String> getToken() {
        return lock.acquireLock().thenCompose(token -> {
            try {
                Instant now = Instant.now();
                if (lastTokenResponse != null && validTo.isAfter(now)) {
                    return CompletableFuture.completedFuture(lastTokenResponse.accessToken());
                }

                if (lastRequestTime != null) {
                    long timeToWait = lastRequestTime.plusSeconds(1).getEpochSecond() - now.getEpochSecond();
                    if (timeToWait > 0) {
                        try {
                            Thread.sleep(timeToWait * 1000);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                }

                lastRequestTime = Instant.now();
                lastTokenResponse = requestToken().get();
                validTo = Instant.now().plusSeconds(lastTokenResponse.expiresInSeconds());
                return CompletableFuture.completedFuture(lastTokenResponse.accessToken());
            } catch (Exception e) {
                return CompletableFuture.failedFuture(new VaasAuthenticationException("Failed to get token", e));
            } finally {
                token.releaseLock();
            }
        }).toCompletableFuture();
    }

    private CompletableFuture<TokenResponse> requestToken() {
        String form = tokenRequestToForm();
        HttpRequest request = HttpRequest.newBuilder(tokenUrl)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenCompose(response -> {
                    if (response.statusCode() != 200) {
                        return CompletableFuture.failedFuture(
                                new VaasAuthenticationException("Identity provider returned status code "
                                        + response.statusCode() + ": " + extractErrorDescription(response.body())));
                    }

                    var tokenResponse = JsonParser.parseString(response.body()).getAsJsonObject();
                    var accessToken = tokenResponse.get("access_token").getAsString();
                    int expiresIn = tokenResponse.get("expires_in").getAsInt();

                    return CompletableFuture.completedFuture(new TokenResponse(accessToken, expiresIn));
                });
    }

    private String extractErrorDescription(String responseBody) {
        try {
            JsonObject errorResponse = JsonParser.parseString(responseBody).getAsJsonObject();
            return errorResponse.has("error_description") ? errorResponse.get("error_description").getAsString()
                    : "Unknown error";
        } catch (Exception e) {
            return "Unable to parse error description: " + e.getMessage();
        }
    }

    protected abstract String tokenRequestToForm();
}