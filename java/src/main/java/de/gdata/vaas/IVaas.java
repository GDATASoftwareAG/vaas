package de.gdata.vaas;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.CompletableFuture;

import de.gdata.vaas.messages.VaasVerdict;
import de.gdata.vaas.options.ForFileOptions;
import de.gdata.vaas.options.ForSha256Options;
import de.gdata.vaas.options.ForStreamOptions;
import de.gdata.vaas.options.ForUrlOptions;

public interface IVaas {
    public CompletableFuture<VaasVerdict> forSha256(Sha256 sha256) throws  URISyntaxException, IOException, InterruptedException;
    public CompletableFuture<VaasVerdict> forSha256(Sha256 sha256, ForSha256Options options) throws URISyntaxException, IOException, InterruptedException;
    public CompletableFuture<VaasVerdict> forStream(InputStream stream, long contentLength) throws URISyntaxException, IOException, InterruptedException;
    public CompletableFuture<VaasVerdict> forStream(InputStream stream, long contentLength, ForStreamOptions options) throws URISyntaxException, IOException, InterruptedException;
    public CompletableFuture<VaasVerdict> forFile(Path file) throws NoSuchAlgorithmException, IOException, URISyntaxException, InterruptedException;
    public CompletableFuture<VaasVerdict> forFile(Path file, ForFileOptions options) throws NoSuchAlgorithmException, IOException, URISyntaxException, InterruptedException;
    public CompletableFuture<VaasVerdict> forUrl(URL url) throws URISyntaxException, IOException, InterruptedException;
    public CompletableFuture<VaasVerdict> forUrl(URL url, ForUrlOptions options) throws URISyntaxException, IOException, InterruptedException;

}
