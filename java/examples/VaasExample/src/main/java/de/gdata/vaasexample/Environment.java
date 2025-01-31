package de.gdata.vaasexample;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Environment {
    public String clientId;
    public String clientSecret;
    public String userName;
    public String password;
    public String vaasUrl;
    public String tokenUrl;

    public Environment() {
        clientId = System.getenv("CLIENT_ID");
        clientSecret = System.getenv("CLIENT_SECRET");
        userName = System.getenv("VAAS_USER_NAME");
        password = System.getenv("VAAS_PASSWORD");
        vaasUrl = System.getenv("VAAS_URL");
        if (vaasUrl == null) {
            vaasUrl = "wss://gateway.staging.vaas.gdatasecurity.de";
        }
        tokenUrl = System.getenv("TOKEN_URL");
        if (tokenUrl == null) {
            tokenUrl = "https://account-staging.gdata.de/realms/vaas-staging/protocol/openid-connect/token";
        }
    }

    public static String getenv(String key) {
        var value = System.getenv(key);
        if (value == null) {
            throw new IllegalStateException("The environment variable " + key + " must be set.");
        }
        return value;
    }
}
