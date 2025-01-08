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
import de.gdata.vaas.exceptions.VaasClientException;
import de.gdata.vaas.exceptions.VaasServerException;
import de.gdata.vaas.messages.VaasVerdict;
import de.gdata.vaas.options.ForFileOptions;
import de.gdata.vaas.options.ForSha256Options;
import de.gdata.vaas.options.ForStreamOptions;
import de.gdata.vaas.options.ForUrlOptions;

public interface IVaas {
    public CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256) throws  URISyntaxException, IOException, InterruptedException, VaasClientException, VaasAuthenticationException;
    public CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256, ForSha256Options options) throws URISyntaxException, IOException, InterruptedException, VaasClientException, VaasAuthenticationException;
    public VaasVerdict forSha256(Sha256 sha256) throws  URISyntaxException, IOException, InterruptedException, VaasClientException, VaasAuthenticationException, ExecutionException;
    public VaasVerdict forSha256(Sha256 sha256, ForSha256Options options) throws URISyntaxException, IOException, InterruptedException, VaasClientException, VaasAuthenticationException, ExecutionException;
    public CompletableFuture<VaasVerdict> forStreamAsync(InputStream stream, long contentLength) throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException;
    public CompletableFuture<VaasVerdict> forStreamAsync(InputStream stream, long contentLength, ForStreamOptions options) throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException;
    public VaasVerdict forStream(InputStream stream, long contentLength) throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException, ExecutionException;
    public VaasVerdict forStream(InputStream stream, long contentLength, ForStreamOptions options) throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException, ExecutionException;    
    public CompletableFuture<VaasVerdict> forFileAsync(Path file) throws NoSuchAlgorithmException, IOException, URISyntaxException, InterruptedException, VaasAuthenticationException;
    public CompletableFuture<VaasVerdict> forFileAsync(Path file, ForFileOptions options) throws NoSuchAlgorithmException, IOException, URISyntaxException, InterruptedException, VaasAuthenticationException;
    public VaasVerdict forFile(Path file) throws NoSuchAlgorithmException, IOException, URISyntaxException, InterruptedException, VaasAuthenticationException, ExecutionException;
    public VaasVerdict forFile(Path file, ForFileOptions options) throws NoSuchAlgorithmException, IOException, URISyntaxException, InterruptedException, VaasAuthenticationException, ExecutionException;
    public CompletableFuture<VaasVerdict> forUrlAsync(URL url) throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException, VaasClientException, VaasServerException;
    public CompletableFuture<VaasVerdict> forUrlAsync(URL url, ForUrlOptions options) throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException, VaasClientException, VaasServerException;
    public VaasVerdict forUrl(URL url) throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException, VaasClientException, VaasServerException, ExecutionException;
    public VaasVerdict forUrl(URL url, ForUrlOptions options) throws URISyntaxException, IOException, InterruptedException, VaasAuthenticationException, VaasClientException, VaasServerException, ExecutionException;    

}
