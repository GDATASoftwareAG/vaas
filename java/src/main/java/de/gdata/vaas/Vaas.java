package de.gdata.vaas;

import de.gdata.vaas.messages.*;
import de.gdata.vaas.options.ForFileOptions;
import de.gdata.vaas.options.ForSha256Options;
import de.gdata.vaas.options.ForStreamOptions;
import de.gdata.vaas.options.ForUrlOptions;
import de.gdata.vaas.exceptions.*;
import lombok.Getter;
import lombok.NonNull;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.net.URIBuilder;
import org.java_websocket.exceptions.WebsocketNotConnectedException;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class Vaas implements AutoCloseable, IVaas {
    private static final int connectionRetryDelayInMs = 1000;
    private static final int connectionTimeoutInMs = 10000;

    @Getter
    @NonNull
    private final VaasConfig config;

    @Getter
    @NonNull
    private VaasOptions options;

    private final IAuthenticator authenticator;
    private final CloseableHttpClient httpClient = HttpClients.createDefault();
    private WebSocketClient client;

    public Vaas(@NonNull VaasConfig config, @NonNull IAuthenticator authenticator) {
        this.config = config;
        this.authenticator = authenticator;
        this.options = new VaasOptions();
    }

    public Vaas(VaasConfig config, IAuthenticator authenticator,
            VaasOptions options) {
        this.config = config;
        this.authenticator = authenticator;
        this.options = options;
    }

    /**
     * Connect and authenticate with the VaaS Backend
     * 
     * @throws IOException                 if an I/O error occurs when getting the
     *                                     token from the identity provider
     * @throws InterruptedException        if the operation is interrupted by
     *                                     Thread.interrupt()
     * @throws VaasAuthenticationException if the token returned by the identity
     *                                     provider is invalid
     * @throws TimeoutException            if the connection or authentication to
     *                                     the VaaS backend takes too long
     */
    public void connect() throws IOException, InterruptedException, VaasAuthenticationException, TimeoutException {
        var timer = new SimpleTimer(connectionTimeoutInMs, TimeUnit.MILLISECONDS);
        while (true) {
            if (this.client != null) {
                this.client.close();
            }
            this.client = new WebSocketClient(this.getConfig(), authenticator);
            if (this.client.connectBlocking(timer.getRemainingMs(), TimeUnit.MILLISECONDS)) {
                try {
                    this.client.Authenticate(timer.getRemainingMs(), TimeUnit.MILLISECONDS);
                    break;
                } catch (WebsocketNotConnectedException ignored) {
                } catch (ExecutionException e) {
                    throw new VaasAuthenticationException();
                }
            }
            TimeUnit.MILLISECONDS.sleep(connectionRetryDelayInMs);
        }
    }

    /**
     * Disconnect from the Vaas backend
     *
     * @throws InterruptedException if the operation is interrupted by
     *                              Thread.interrupt()
     */
    public void disconnect() throws InterruptedException {
        if (this.client != null) {
            this.client.closeBlocking();
        }
    }

    private void throwVaasException(ExecutionException e) throws VaasClientException, VaasServerException {
        var errorCause = e.getCause();
        if (errorCause instanceof VaasClientException) {
            throw (VaasClientException) errorCause;
        } else if (errorCause instanceof VaasServerException) {
            throw (VaasServerException) errorCause;
        }
        throw new VaasClientException("Unexpected error.");
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void throwAsUnchecked(Exception exception) throws E {
        throw (E) exception;
    }

    @Override
    public void close() throws Exception {
        try {
            this.disconnect();
        } catch (Exception e) {
            // ignored
        }
    }

    public ClassicHttpResponse SendRequest(URI uri, HttpUriRequestBase requestBase, String requestId)
            throws IOException, InterruptedException {
        var token = this.authenticator.getToken();
        requestBase.addHeader("Authorization", "Bearer " + token);
        requestBase.addHeader("User-Agent", "useragent");
        requestBase.addHeader("tracestate", "vaasrequestid=" + requestId);
        return httpClient.executeOpen(null, requestBase, null);
    }

    @Override
    public CompletableFuture<VaasVerdict> forSha256(Sha256 sha256)
            throws ParseException, URISyntaxException, IOException, InterruptedException {
        var forSha256Options = new ForSha256Options();
        forSha256Options.setUseCache(true);
        forSha256Options.setUseHashLookup(true);
        return this.forSha256(sha256, forSha256Options);
    }

    @Override
    public CompletableFuture<VaasVerdict> forSha256(Sha256 sha256, ForSha256Options options)
            throws URISyntaxException, IOException, ParseException, InterruptedException {

        var reportUri = new URIBuilder(this.config.getUrl())
                .appendPath(String.format("/files/%s/report", sha256.getValue()))
                .setParameter("useCache", String.valueOf(this.options.isUseCache()))
                .setParameter("useHashLookup", String.valueOf(this.options.isUseHashLookup()))
                .build();

        var request = new HttpGet(reportUri);

        if (options.getVaasRequestId() == null || options.getVaasRequestId().isBlank()) {
            options.setVaasRequestId(UUID.randomUUID().toString());
        }

        while (true) {
            var response = this.SendRequest(reportUri, request, options.getVaasRequestId());
            var statusCode = response.getCode();
            var httpEntity = response.getEntity();

            switch (statusCode) {
                case HttpStatus.SC_OK:
                    var jsonString = EntityUtils.toString(httpEntity);
                    var fileReport = UrlReport.fromJson(jsonString);
                    return CompletableFuture.supplyAsync(() -> VaasVerdict.From(fileReport));
                case HttpStatus.SC_ACCEPTED:
                    continue;
                case HttpStatus.SC_UNAUTHORIZED:
                    // TODO throw VaasAuthenticationException
                case HttpStatus.SC_BAD_REQUEST:
                default:
                    // TODO throw VaasException
            }
        }
    }

    @Override
    public CompletableFuture<VaasVerdict> forFile(Path file)
            throws NoSuchAlgorithmException, IOException, ParseException, URISyntaxException, InterruptedException {
                var forFileOptions = new ForFileOptions();
                forFileOptions.setUseCache(true);
                forFileOptions.setUseHashLookup(true);
                return forFile(file, forFileOptions);
            }

    @Override
    public CompletableFuture<VaasVerdict> forFile(Path file, ForFileOptions options)
            throws NoSuchAlgorithmException, IOException, ParseException, URISyntaxException, InterruptedException {
        var sha256 = new Sha256(file);
        var forSha256Options = new ForSha256Options(options.isUseCache(), options.isUseHashLookup(),
                options.getVaasRequestId());
        var vaasVerdict = forSha256(sha256, forSha256Options).join();
        var verdictWithoutDetection = vaasVerdict.getVerdict() == Verdict.MALICIOUS
                || vaasVerdict.getVerdict() == Verdict.PUP && vaasVerdict.getDetection() == null
                || vaasVerdict.getDetection().isBlank();

        if (vaasVerdict.getVerdict() != Verdict.UNKNOWN && verdictWithoutDetection
                && vaasVerdict.getFileType() != null
                && !vaasVerdict.getFileType().isBlank() && vaasVerdict.getMimeType() != null
                && !vaasVerdict.getMimeType().isEmpty()) {

            return CompletableFuture.supplyAsync(() -> {
                return vaasVerdict;
            });
        }

        var inputstream = Files.newInputStream(file, StandardOpenOption.READ);
        var forStreamOptions = new ForStreamOptions();
        forStreamOptions.setUseHashLookup(options.isUseHashLookup());
        forStreamOptions.setVaasRequestId(options.getVaasRequestId());
        return forStream(inputstream, forStreamOptions);

    }

    @Override
    public CompletableFuture<VaasVerdict> forStream(InputStream stream)
            throws URISyntaxException, IOException, InterruptedException, ParseException {
                var forStreamOptions = new ForStreamOptions();
                forStreamOptions.setUseHashLookup(true);
                return forStream(stream, forStreamOptions);
            }

    @Override
    public CompletableFuture<VaasVerdict> forStream(InputStream stream, ForStreamOptions options)
            throws URISyntaxException, IOException, InterruptedException, ParseException {
        var reportUri = new URIBuilder(this.config.getUrl())
                .appendPath(String.format("/files"))
                .setParameter("useHashLookup", String.valueOf(this.options.isUseHashLookup()))
                .build();

        var request = new HttpPost(reportUri);
        var inputStreamEntity = new InputStreamEntity(stream, null);
        request.setEntity(inputStreamEntity);

        var response = this.SendRequest(reportUri, request, options.getVaasRequestId());
        var statusCode = response.getCode();
        var httpEntity = response.getEntity();
        if (statusCode < HttpStatus.SC_SUCCESS || statusCode > HttpStatus.SC_REDIRECTION) {
            System.out.println("TODO Fehler");
        }

        var jsonString = EntityUtils.toString(httpEntity);
        var fileResponseStarted = FileAnalysisStarted.fromJson(jsonString);
        var sha256 = new Sha256(fileResponseStarted.getSha256());
        var forSha256Options = new ForSha256Options();
        forSha256Options.setUseHashLookup(options.isUseHashLookup());
        forSha256Options.setVaasRequestId(options.getVaasRequestId());

        return forSha256(sha256, forSha256Options);
    }

    @Override
    public CompletableFuture<VaasVerdict> forUrl(URL url) throws URISyntaxException, IOException, InterruptedException, ParseException {
        var forUrlOptions = new ForUrlOptions();
        forUrlOptions.setUseHashLookup(true);
        return forUrl(url, forUrlOptions);
    }

    @Override
    public CompletableFuture<VaasVerdict> forUrl(URL url, ForUrlOptions options) throws URISyntaxException, IOException, InterruptedException, ParseException {
        var urlAnalysisUri = new URIBuilder(this.config.getUrl())
                .appendPath(String.format("/urls"))
                .setParameter("useHashLookup", String.valueOf(this.options.isUseHashLookup()))
                .build();

        var httpPost = new HttpPost(urlAnalysisUri);
        var urlAnalysisRequest = new UrlAnalysisRequest(url.toString(), options.isUseHashLookup());
        var stringEntity = new StringEntity(UrlAnalysisRequest.ToJson(urlAnalysisRequest), ContentType.APPLICATION_JSON);
        httpPost.setEntity(stringEntity);
        var urlAnalysisResponse = this.SendRequest(urlAnalysisUri, httpPost, options.getVaasRequestId());
        var statusCode = urlAnalysisResponse.getCode();
        var httpEntity = urlAnalysisResponse.getEntity();
        if (statusCode < HttpStatus.SC_SUCCESS || statusCode > HttpStatus.SC_REDIRECTION) {
            System.out.println("TODO Fehler");
        }
        var jsonString = EntityUtils.toString(httpEntity);
        var urlAnalysisStarted = UrlAnalysisStarted.fromJson(jsonString);

        while(true) {
            var reportUri = new URIBuilder(this.config.getUrl())
            .appendPath(String.format("/urls/%s/report", urlAnalysisStarted.getId()))
            .build();

            var httpGet = new HttpGet(reportUri);
            if (options.getVaasRequestId() == null || options.getVaasRequestId().isBlank()) {
                options.setVaasRequestId(UUID.randomUUID().toString());
            }
            var reportResponse = this.SendRequest(reportUri, httpGet, options.getVaasRequestId());
            var reportResponseStatusCode = reportResponse.getCode();
            var reportResponseHttpEntity = reportResponse.getEntity();

            switch (reportResponseStatusCode) {
                case HttpStatus.SC_OK:
                    var urlReportString = EntityUtils.toString(reportResponseHttpEntity);
                    var urlReport = UrlReport.fromJson(urlReportString);
                    return CompletableFuture.supplyAsync(() -> VaasVerdict.From(urlReport));
                case HttpStatus.SC_ACCEPTED:
                    continue;
                case HttpStatus.SC_UNAUTHORIZED:
                    // TODO throw VaasAuthenticationException
                case HttpStatus.SC_BAD_REQUEST:
                default:
                    // TODO throw VaasException
            }        
        }
    }
}
