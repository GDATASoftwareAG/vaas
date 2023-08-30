package de.gdata.vaas;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.Getter;
import lombok.NonNull;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class ResourceOwnerPasswordAuthenticator implements IAuthenticator {

    @Getter
    private String clientId, username, password;

    @Getter
    @NonNull
    private URI tokenEndpoint;

    public ResourceOwnerPasswordAuthenticator(String clientId, String username, String password)
            throws URISyntaxException {
        this.tokenEndpoint = new URI("https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token");
        this.clientId = clientId;
        this.username = username;
        this.password = password;
    }

    public ResourceOwnerPasswordAuthenticator(String clientId, String username, String password, String tokenEndpoint)
            throws URISyntaxException {
        this.tokenEndpoint = new URI(tokenEndpoint);
        this.clientId = clientId;
        this.username = username;
        this.password = password;
    }

    private String encodeValue(String value) throws UnsupportedEncodingException {
        return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
    }

    public String getToken() throws IOException, InterruptedException {
        Map<String, String> requestParams = new HashMap<>();
        requestParams.put("client_id", this.clientId);
        requestParams.put("grant_type", "password");
        requestParams.put("username", this.username);
        requestParams.put("password", this.password);
        String UriWithParameters = requestParams.keySet().stream()
                .map(key -> {
                    try {
                        return key + "=" + encodeValue(requestParams.get(key));
                    } catch (UnsupportedEncodingException e) {
                        return "";
                    }
                })
                .collect(Collectors.joining("&"));
        var request = HttpRequest
                .newBuilder(tokenEndpoint)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(UriWithParameters))
                .build();

        var response = HttpClient
                .newBuilder()
                .build()
                .send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IOException("Failed to upload file. HTTP Status Code: " + response.statusCode() + " Error: "
                    + response.body());
        }
        JsonObject bodyJsonObject = JsonParser.parseString(response.body()).getAsJsonObject();
        JsonElement tokenJsonElement = bodyJsonObject.get("access_token");
        return tokenJsonElement.getAsString();
    }
}
