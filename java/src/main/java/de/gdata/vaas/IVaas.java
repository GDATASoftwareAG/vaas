package de.gdata.vaas;

import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.exceptions.VaasClientException;
import de.gdata.vaas.exceptions.VaasServerException;
import de.gdata.vaas.messages.VaasVerdict;
import de.gdata.vaas.options.ForFileOptions;
import de.gdata.vaas.options.ForSha256Options;
import de.gdata.vaas.options.ForStreamOptions;
import de.gdata.vaas.options.ForUrlOptions;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;

public interface IVaas {
    /**
     * Asynchronously retrieves a {@link CompletableFuture} containing the
     * {@link VaasVerdict} for the given SHA-256 hash.
     *
     * @param sha256 the SHA-256 hash to retrieve the verdict for
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     * the hash
     */
    CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256);

    /**
     * Asynchronously retrieves a {@link CompletableFuture} containing the
     * {@link VaasVerdict} for the given SHA-256 hash.
     *
     * @param sha256  the SHA-256 hash to retrieve the verdict for
     * @param options The options to customize the request, such as using the cache
     *                and hash lookup. If not set the global options passed to the Vaas constructor are used.
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     * the hash
     */
    CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256, ForSha256Options options);

    /**
     * Retrieves a {@link VaasVerdict} for the given SHA-256 hash.
     *
     * @param sha256 the SHA-256 hash to retrieve the verdict for
     * @return the {@link VaasVerdict} for the given SHA-256 hash
     * @throws InterruptedException        If the thread is interrupted
     * @throws VaasAuthenticationException If there is an authentication error. Don't repeat the request. Check your credentials and token endpoint.
     * @throws VaasClientException         The request is malformed or cannot be completed. Recommended actions: Don't repeat the request. Log. Analyze the error.
     * @throws VaasServerException         The server encountered an internal error. Recommended actions: You may retry the request after a certain delay. If the problem persists contact G DATA.
     */
    VaasVerdict forSha256(Sha256 sha256) throws InterruptedException, VaasAuthenticationException, VaasClientException, VaasServerException;

    /**
     * Retrieves a {@link VaasVerdict} for the given SHA-256 hash.
     *
     * @param sha256  the SHA-256 hash to retrieve the verdict for
     * @param options The options to customize the request, such as using the cache
     *                and hash lookup. If not set the global options passed to the Vaas constructor are used.
     * @return the {@link VaasVerdict} for the given SHA-256 hash
     * @throws InterruptedException        If the thread is interrupted
     * @throws VaasAuthenticationException If there is an authentication error. Don't repeat the request. Check your credentials and token endpoint.
     * @throws VaasClientException         The request is malformed or cannot be completed. Recommended actions: Don't repeat the request. Log. Analyze the error.
     * @throws VaasServerException         The server encountered an internal error. Recommended actions: You may retry the request after a certain delay. If the problem persists contact G DATA.
     */
    VaasVerdict forSha256(Sha256 sha256, ForSha256Options options)
            throws InterruptedException, VaasAuthenticationException, VaasClientException, VaasServerException;

    /**
     * Asynchronously processes a given input stream and returns a
     * {@link CompletableFuture}
     * containing the {@link VaasVerdict}.
     *
     * @param stream        the input stream to be processed
     * @param contentLength the length of the content in the input stream
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict}
     */
    CompletableFuture<VaasVerdict> forStreamAsync(InputStream stream, long contentLength);

    /**
     * Asynchronously processes a given input stream and returns a
     * {@link CompletableFuture}
     * containing the {@link VaasVerdict}.
     *
     * @param stream        the input stream to be processed
     * @param contentLength the length of the content in the input stream
     * @param options       The options to customize the request, such as using the
     *                      hash lookup. If not set the global options passed to the Vaas constructor are used.
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict}
     */
    CompletableFuture<VaasVerdict> forStreamAsync(InputStream stream, long contentLength, ForStreamOptions options);

    /**
     * Processes a given input stream and returns the {@link VaasVerdict}.
     *
     * @param stream        the input stream to be processed
     * @param contentLength the length of the content in the input stream
     * @return the {@link VaasVerdict}
     * @throws InterruptedException        If the thread is interrupted
     * @throws VaasAuthenticationException If there is an authentication error. Don't repeat the request. Check your credentials and token endpoint.
     * @throws VaasClientException         The request is malformed or cannot be completed. Recommended actions: Don't repeat the request. Log. Analyze the error.
     * @throws VaasServerException         The server encountered an internal error. Recommended actions: You may retry the request after a certain delay. If the problem persists contact G DATA.
     */
    VaasVerdict forStream(InputStream stream, long contentLength)
            throws InterruptedException, VaasAuthenticationException, VaasClientException, VaasServerException;

    /**
     * Processes a given input stream and returns the {@link VaasVerdict}.
     *
     * @param stream        the input stream to be processed
     * @param contentLength the length of the content in the input stream
     * @param options       The options to customize the request, such as using the
     *                      hash lookup. If not set the global options passed to the Vaas constructor are used.
     * @return the {@link VaasVerdict}
     * @throws InterruptedException        If the thread is interrupted
     * @throws VaasAuthenticationException If there is an authentication error. Don't repeat the request. Check your credentials and token endpoint.
     * @throws VaasClientException         The request is malformed or cannot be completed. Recommended actions: Don't repeat the request. Log. Analyze the error.
     * @throws VaasServerException         The server encountered an internal error. Recommended actions: You may retry the request after a certain delay. If the problem persists contact G DATA.
     */
    VaasVerdict forStream(InputStream stream, long contentLength, ForStreamOptions options)
            throws InterruptedException, VaasAuthenticationException, VaasClientException, VaasServerException;

    /**
     * Asynchronously processes a file and returns a {@link CompletableFuture}
     * containing the {@link VaasVerdict}.
     *
     * @param file the {@link Path} to the file to be processed
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     * the file
     * @throws VaasClientException if the SHA-256 algorithm for hash lookup is not available on the client
     * @throws IOException         if an I/O error occurs
     */
    CompletableFuture<VaasVerdict> forFileAsync(Path file) throws IOException, VaasClientException;

    /**
     * Asynchronously processes a file and returns a {@link CompletableFuture}
     * containing the {@link VaasVerdict}.
     *
     * @param file    the {@link Path} to the file to be processed
     * @param options The options to customize the request, such as using the cache
     *                and hash lookup. If not set the global options passed to the Vaas constructor are used.
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     * the file
     * @throws IOException         if an I/O error occurs
     * @throws VaasClientException if the SHA-256 algorithm for hash lookup is not available on the client
     */
    CompletableFuture<VaasVerdict> forFileAsync(Path file, ForFileOptions options) throws IOException, VaasClientException;

    /**
     * Processes a file and returns the {@link VaasVerdict}.
     *
     * @param file the {@link Path} to the file to be processed
     * @return the {@link VaasVerdict} for the file
     * @throws IOException                 if an I/O error occurs
     * @throws InterruptedException        If the thread is interrupted
     * @throws VaasAuthenticationException If there is an authentication error. Don't repeat the request. Check your credentials and token endpoint.
     * @throws VaasClientException         The request is malformed or cannot be completed. Recommended actions: Don't repeat the request. Log. Analyze the error.
     * @throws VaasServerException         The server encountered an internal error. Recommended actions: You may retry the request after a certain delay. If the problem persists contact G DATA.
     */
    VaasVerdict forFile(Path file) throws InterruptedException, IOException, VaasAuthenticationException, VaasClientException, VaasServerException;

    /**
     * Processes a file and returns the {@link VaasVerdict}.
     *
     * @param file    the {@link Path} to the file to be processed
     * @param options The options to customize the request, such as using the cache
     *                and hash lookup. If not set the global options passed to the Vaas constructor are used.
     * @return the {@link VaasVerdict} for the file
     * @throws IOException                 if an I/O error occurs
     * @throws InterruptedException        If the thread is interrupted
     * @throws VaasAuthenticationException If there is an authentication error. Don't repeat the request. Check your credentials and token endpoint.
     * @throws VaasClientException         The request is malformed or cannot be completed. Recommended actions: Don't repeat the request. Log. Analyze the error.
     * @throws VaasServerException         The server encountered an internal error. Recommended actions: You may retry the request after a certain delay. If the problem persists contact G DATA.
     */
    VaasVerdict forFile(Path file, ForFileOptions options) throws InterruptedException, IOException, VaasAuthenticationException, VaasClientException, VaasServerException;

    /**
     * Asynchronously retrieves a {@link CompletableFuture} containing the
     * {@link VaasVerdict} for the given URL.
     *
     * @param url the URL to retrieve the verdict for
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for the URL
     */
    CompletableFuture<VaasVerdict> forUrlAsync(URL url);

    /**
     * Asynchronously retrieves a {@link CompletableFuture} containing the
     * {@link VaasVerdict} for the given URL.
     *
     * @param url     the URL to retrieve the verdict for
     * @param options The options to customize the request, such as using hash
     *                lookup. If not set the global options passed to the Vaas constructor are used.
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for the URL
     */
    CompletableFuture<VaasVerdict> forUrlAsync(URL url, ForUrlOptions options);

    /**
     * Retrieves a {@link VaasVerdict} for the given URL.
     *
     * @param url the URL to retrieve the verdict for
     * @return the {@link VaasVerdict} for the URL
     * @throws InterruptedException        If the thread is interrupted
     * @throws VaasAuthenticationException If there is an authentication error. Don't repeat the request. Check your credentials and token endpoint.
     * @throws VaasClientException         The request is malformed or cannot be completed. Recommended actions: Don't repeat the request. Log. Analyze the error.
     * @throws VaasServerException         The server encountered an internal error. Recommended actions: You may retry the request after a certain delay. If the problem persists contact G DATA.
     */
    VaasVerdict forUrl(URL url) throws InterruptedException, VaasAuthenticationException, VaasClientException, VaasServerException;

    /**
     * Retrieves a {@link VaasVerdict} for the given URL.
     *
     * @param url     the URL to retrieve the verdict for
     * @param options The options to customize the request, such as using hash
     *                lookup. If not set the global options passed to the Vaas constructor are used.
     * @return the {@link VaasVerdict} for the URL
     * @throws InterruptedException        If the thread is interrupted
     * @throws VaasAuthenticationException If there is an authentication error. Don't repeat the request. Check your credentials and token endpoint.
     * @throws VaasClientException         The request is malformed or cannot be completed. Recommended actions: Don't repeat the request. Log. Analyze the error.
     * @throws VaasServerException         The server encountered an internal error. Recommended actions: You may retry the request after a certain delay. If the problem persists contact G DATA.
     */
    VaasVerdict forUrl(URL url, ForUrlOptions options) throws InterruptedException, VaasAuthenticationException, VaasClientException, VaasServerException;

}
