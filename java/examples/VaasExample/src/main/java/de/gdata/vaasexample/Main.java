package de.gdata.vaasexample;

import de.gdata.vaas.Vaas;
import de.gdata.vaas.WsConfig;

import java.net.URI;
import java.nio.file.Path;

public class Main {
    public static void main(String[] args) throws Exception {
        var clientId = System.getenv("CLIENT_ID");
        var clientSecret = System.getenv("CLIENT_SECRET");
        var scanPath = System.getenv("SCAN_PATH");

        var config = new WsConfig(
                clientId,
                clientSecret,
                new URI("https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token"),
                new URI("wss://gateway-vaas.gdatasecurity.de"));
        var vaas = new Vaas(config);
        vaas.connect();

        var file = Path.of(scanPath);
        var verdict = vaas.forFile(file);
        vaas.disconnect();
        System.out.printf("File %s was detected as %s", file, verdict.getVerdict());
    }
}