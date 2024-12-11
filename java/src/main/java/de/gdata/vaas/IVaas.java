package de.gdata.vaas;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.CompletableFuture;

import org.apache.hc.core5.http.ParseException;

import de.gdata.vaas.messages.VaasVerdict;
import de.gdata.vaas.options.ForFileOptions;
import de.gdata.vaas.options.ForSha256Options;
import de.gdata.vaas.options.ForStreamOptions;
import de.gdata.vaas.options.ForUrlOptions;

public interface IVaas {
    public CompletableFuture<VaasVerdict> forSha256(Sha256 sha256) throws ParseException, URISyntaxException, IOException, InterruptedException;
    public CompletableFuture<VaasVerdict> forSha256(Sha256 sha256, ForSha256Options options) throws URISyntaxException, IOException, ParseException, InterruptedException;
    public CompletableFuture<VaasVerdict> forStream(InputStream stream) throws URISyntaxException, IOException, InterruptedException, ParseException;
    public CompletableFuture<VaasVerdict> forStream(InputStream stream, ForStreamOptions options) throws URISyntaxException, IOException, InterruptedException, ParseException;
    public CompletableFuture<VaasVerdict> forFile(Path file) throws NoSuchAlgorithmException, IOException, ParseException, URISyntaxException, InterruptedException;
    public CompletableFuture<VaasVerdict> forFile(Path file, ForFileOptions options) throws NoSuchAlgorithmException, IOException, ParseException, URISyntaxException, InterruptedException;
    public CompletableFuture<VaasVerdict> forUrl(URL url) throws URISyntaxException, IOException, InterruptedException, ParseException;
    public CompletableFuture<VaasVerdict> forUrl(URL url, ForUrlOptions options) throws URISyntaxException, IOException, InterruptedException, ParseException;

}
