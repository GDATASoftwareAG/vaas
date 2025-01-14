package de.gdata.vaasexample;

import io.github.cdimascio.dotenv.Dotenv;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Environment {
    private static final Dotenv dotenv = Dotenv.configure()
            .ignoreIfMissing()
            .load();
    public String clientId;
    public String clientSecret;
    public String vaasClientId;
    public String userName;
    public String password;
    public String vaasUrl;
    public String tokenUrl;

    public Environment() {
        clientId = System.getenv("CLIENT_ID");
        if (clientId == null || clientId.isBlank()) {
            clientId = dotenv.get("CLIENT_ID");
        }
        clientSecret = System.getenv("CLIENT_SECRET");
        if (clientSecret == null || clientSecret.isBlank()) {
            clientSecret = dotenv.get("CLIENT_SECRET");
        }
        userName = System.getenv("VAAS_USER_NAME");
        if (userName == null || userName.isBlank()) {
            userName = dotenv.get("VAAS_USER_NAME");
        }
        password = System.getenv("VAAS_PASSWORD");
        if (password == null || password.isBlank()) {
            password = dotenv.get("VAAS_PASSWORD");
        }
        vaasUrl = System.getenv("VAAS_URL");
        if (vaasUrl == null || vaasUrl.isBlank()) {
            vaasUrl = dotenv.get("VAAS_URL");
        }
        tokenUrl = System.getenv("TOKEN_URL");
        if (tokenUrl == null || tokenUrl.isBlank()) {
            tokenUrl = dotenv.get("TOKEN_URL");
        }
        vaasClientId = System.getenv("VAAS_CLIENT_ID");
        if (vaasClientId == null || vaasClientId.isBlank()) {
            vaasClientId = dotenv.get("VAAS_CLIENT_ID");
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
