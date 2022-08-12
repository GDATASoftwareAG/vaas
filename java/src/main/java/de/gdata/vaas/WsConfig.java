package de.gdata.vaas;

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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;


public class WsConfig {

    private String encodeValue(String value) throws UnsupportedEncodingException {
        return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
    }

    public String getToken() throws URISyntaxException, IOException, InterruptedException {
        if (token == null) {
            Map<String, String> requestParams = new HashMap<>();
            requestParams.put("client_id", getClientID());
            requestParams.put("grant_type", "client_credentials");
            requestParams.put("client_secret", getClientSecret());
            String UriWithParameters = requestParams.keySet().stream()
                    .map(key -> {
                        try { return key + "=" + encodeValue(requestParams.get(key));}
                        catch (UnsupportedEncodingException e) { return ""; }                        
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
                throw new IOException("Failed to upload file. HTTP Status Code: " + response.statusCode() + " Error: " + response.body());
            }
            JsonObject bodyJsonObject = JsonParser.parseString(response.body()).getAsJsonObject();
            JsonElement tokenJsonElement = bodyJsonObject.get("access_token");
            token = tokenJsonElement.getAsString();
        } return token;
    }

    private String token;
    @Getter
    private String clientID, clientSecret;

    @Getter @Setter @NonNull
    private URI url;

    @Getter @Setter @NonNull
    private URI tokenEndpoint;

    @Getter @Setter
    private int PullDelayMs;

    public WsConfig(String clientId, String clientSecret) throws URISyntaxException {
        this(clientId, clientSecret, 
            new URI("https://keycloak-vaas.gdatasecurity.de"), 
            new URI("wss://gateway-vaas.gdatasecurity.de"));
    }

    public WsConfig(String clientId, String clientSecret, URI tokenEndpoint, URI url) throws URISyntaxException {
        this.clientID = clientId;
        this.clientSecret = clientSecret;
        this.tokenEndpoint = tokenEndpoint;
        this.url = url;
        this.PullDelayMs = 100;
    }
}
