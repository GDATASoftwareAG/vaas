package de.gdata.vaas;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.messages.VaasVerdict;
import de.gdata.vaas.options.ForFileOptions;
import de.gdata.vaas.options.ForSha256Options;
import de.gdata.vaas.options.ForStreamOptions;
import de.gdata.vaas.options.ForUrlOptions;

public interface IVaas {
    CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256) throws IOException, InterruptedException, VaasAuthenticationException;
    CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256, ForSha256Options options) throws IOException, InterruptedException, VaasAuthenticationException;
    VaasVerdict forSha256(Sha256 sha256) throws  URISyntaxException, IOException, InterruptedException, VaasAuthenticationException, ExecutionException;
    VaasVerdict forSha256(Sha256 sha256, ForSha256Options options) throws InterruptedException, ExecutionException, IOException, VaasAuthenticationException;
    CompletableFuture<VaasVerdict> forStreamAsync(InputStream stream, long contentLength) throws IOException, InterruptedException, VaasAuthenticationException;
    CompletableFuture<VaasVerdict> forStreamAsync(InputStream stream, long contentLength, ForStreamOptions options) throws IOException, InterruptedException, VaasAuthenticationException;
    VaasVerdict forStream(InputStream stream, long contentLength) throws InterruptedException, ExecutionException, IOException, VaasAuthenticationException;
    VaasVerdict forStream(InputStream stream, long contentLength, ForStreamOptions options) throws InterruptedException, ExecutionException, IOException, VaasAuthenticationException;
    CompletableFuture<VaasVerdict> forFileAsync(Path file) throws IOException, InterruptedException, VaasAuthenticationException, NoSuchAlgorithmException;
    CompletableFuture<VaasVerdict> forFileAsync(Path file, ForFileOptions options) throws IOException, InterruptedException, VaasAuthenticationException, NoSuchAlgorithmException;
    VaasVerdict forFile(Path file, ForFileOptions options) throws NoSuchAlgorithmException, InterruptedException, ExecutionException, IOException, VaasAuthenticationException;
    CompletableFuture<VaasVerdict> forUrlAsync(URL url) throws IOException, InterruptedException, VaasAuthenticationException;
    CompletableFuture<VaasVerdict> forUrlAsync(URL url, ForUrlOptions options) throws IOException, InterruptedException, VaasAuthenticationException;
    VaasVerdict forUrl(URL url, ForUrlOptions options) throws InterruptedException, ExecutionException, IOException, VaasAuthenticationException;
    VaasVerdict forUrl(URL url) throws InterruptedException, ExecutionException, IOException, VaasAuthenticationException;

}
