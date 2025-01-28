package de.gdata.vaas;

import de.gdata.vaas.exceptions.VaasAuthenticationException;
import de.gdata.vaas.messages.VaasVerdict;
import de.gdata.vaas.options.ForFileOptions;
import de.gdata.vaas.options.ForSha256Options;
import de.gdata.vaas.options.ForStreamOptions;
import de.gdata.vaas.options.ForUrlOptions;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public interface IVaas {
    /**
     * Asynchronously retrieves a {@link CompletableFuture} containing the
     * {@link VaasVerdict} for the given SHA-256 hash.
     * This method uses cache and hash lookup options by default.
     *
     * @param sha256 the SHA-256 hash to retrieve the verdict for
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     *         the hash
     * @throws VaasAuthenticationException If there is an authentication error.
     */
    CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256) throws VaasAuthenticationException;

    /**
     * Asynchronously retrieves a {@link CompletableFuture} containing the
     * {@link VaasVerdict} for the given SHA-256 hash.
     *
     * @param sha256  the SHA-256 hash to retrieve the verdict for
     * @param options The options to customize the request, such as using the cache
     *                and hash lookup.
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     *         the hash
     * @throws VaasAuthenticationException If there is an authentication error.
     */
    CompletableFuture<VaasVerdict> forSha256Async(Sha256 sha256, ForSha256Options options)
            throws VaasAuthenticationException;

    /**
     * Retrieves a {@link VaasVerdict} for the given SHA-256 hash.
     * This method uses cache and hash lookup options by default.
     *
     * @param sha256 the SHA-256 hash to retrieve the verdict for
     * @return the {@link VaasVerdict} for the given SHA-256 hash
     * @throws InterruptedException        if the thread is interrupted while
     *                                     waiting for the result
     * @throws ExecutionException          if the computation threw an exception
     * @throws VaasAuthenticationException if there is an authentication error
     */
    VaasVerdict forSha256(Sha256 sha256) throws InterruptedException, ExecutionException, VaasAuthenticationException;

    /**
     * Retrieves a {@link VaasVerdict} for the given SHA-256 hash.
     * This method uses cache and hash lookup options by default.
     *
     * @param sha256  the SHA-256 hash to retrieve the verdict for
     * @param options The options to customize the request, such as using the cache
     *                and hash lookup.
     * @return the {@link VaasVerdict} for the given SHA-256 hash
     * @throws InterruptedException        if the thread is interrupted while
     *                                     waiting for the result
     * @throws ExecutionException          if the computation threw an exception
     * @throws VaasAuthenticationException if there is an authentication error
     */
    VaasVerdict forSha256(Sha256 sha256, ForSha256Options options)
            throws InterruptedException, ExecutionException, VaasAuthenticationException;

    /**
     * Asynchronously processes a given input stream and returns a
     * {@link CompletableFuture}
     * containing the {@link VaasVerdict}.
     * This method uses the hash lookup option by default.
     *
     * @param stream        the input stream to be processed
     * @param contentLength the length of the content in the input stream
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict}
     * @throws VaasAuthenticationException if authentication fails
     */
    CompletableFuture<VaasVerdict> forStreamAsync(InputStream stream, long contentLength)
            throws VaasAuthenticationException;

    /**
     * Asynchronously processes a given input stream and returns a
     * {@link CompletableFuture}
     * containing the {@link VaasVerdict}.
     *
     * @param inputStream   the input stream to be processed
     * @param contentLength the length of the content in the input stream
     * @param options       The options to customize the request, such as using the
     *                      hash lookup.
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict}
     * @throws VaasAuthenticationException if authentication fails
     */
    CompletableFuture<VaasVerdict> forStreamAsync(InputStream stream, long contentLength, ForStreamOptions options)
            throws VaasAuthenticationException;

    /**
     * Processes a given input stream and returns the {@link VaasVerdict}.
     * This method uses the hash lookup option by default.
     *
     * @param stream        the input stream to be processed
     * @param contentLength the length of the content in the input stream
     * @return the {@link VaasVerdict}
     * @throws InterruptedException        if the operation is interrupted
     * @throws ExecutionException          if the computation threw an exception
     * @throws VaasAuthenticationException if there is an authentication error
     */
    VaasVerdict forStream(InputStream stream, long contentLength)
            throws InterruptedException, ExecutionException, VaasAuthenticationException;

    /**
     * Processes a given input stream and returns the {@link VaasVerdict}.
     *
     * @param stream        the input stream to be processed
     * @param contentLength the length of the content in the input stream
     * @param options       The options to customize the request, such as using the
     *                      hash lookup.
     * @return the {@link VaasVerdict}
     * @throws InterruptedException        if the operation is interrupted
     * @throws ExecutionException          if the computation threw an exception
     * @throws VaasAuthenticationException if there is an authentication error
     */
    VaasVerdict forStream(InputStream stream, long contentLength, ForStreamOptions options)
            throws InterruptedException, ExecutionException, VaasAuthenticationException;

    /**
     * Asynchronously processes a file and returns a {@link CompletableFuture}
     * containing the {@link VaasVerdict}.
     * This method uses default options for file processing, including using the
     * cache and hash lookup.
     *
     * @param file the {@link Path} to the file to be processed
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     *         the file
     * @throws IOException                 if an I/O error occurs
     * @throws VaasAuthenticationException if authentication fails
     * @throws NoSuchAlgorithmException    if the algorithm for hash lookup is not
     *                                     available
     */
    CompletableFuture<VaasVerdict> forFileAsync(Path file)
            throws NoSuchAlgorithmException, IOException, VaasAuthenticationException;

    /**
     * Asynchronously processes a file and returns a {@link CompletableFuture}
     * containing the {@link VaasVerdict}.
     * This method uses default options for file processing, including using the
     * cache and hash lookup.
     *
     * @param file    the {@link Path} to the file to be processed
     * @param options The options to customize the request, such as using the cache
     *                and hash lookup.
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     *         the file
     * @throws IOException                 if an I/O error occurs
     * @throws VaasAuthenticationException if authentication fails
     * @throws NoSuchAlgorithmException    if the algorithm for hash lookup is not
     *                                     available
     */
    CompletableFuture<VaasVerdict> forFileAsync(Path file, ForFileOptions options)
            throws NoSuchAlgorithmException, IOException, VaasAuthenticationException;

    /**
     * Processes a file and returns the {@link VaasVerdict}.
     * This method uses default options for file processing, including using the
     * cache and hash lookup.
     *
     * @param file the {@link Path} to the file to be processed
     * @return the {@link VaasVerdict} for the file
     * @throws ExecutionException
     * @throws IOException                 if an I/O error occurs
     * @throws InterruptedException        if the operation is interrupted
     * @throws VaasAuthenticationException if authentication fails
     * @throws NoSuchAlgorithmException    if the algorithm for hash lookup is not
     *                                     available
     */
    VaasVerdict forFile(Path file) throws NoSuchAlgorithmException, InterruptedException, ExecutionException,
            IOException, VaasAuthenticationException;

    /**
     * Processes a file and returns the {@link VaasVerdict}.
     *
     * @param file    the {@link Path} to the file to be processed
     * @param options The options to customize the request, such as using the cache
     *                and hash lookup.
     * @return the {@link VaasVerdict} for the file
     * @throws ExecutionException
     * @throws IOException                 if an I/O error occurs
     * @throws InterruptedException        if the operation is interrupted
     * @throws VaasAuthenticationException if authentication fails
     * @throws NoSuchAlgorithmException    if the algorithm for hash lookup is not
     *                                     available
     */
    VaasVerdict forFile(Path file, ForFileOptions options) throws NoSuchAlgorithmException, InterruptedException,
            ExecutionException, IOException, VaasAuthenticationException;

    /**
     * Asynchronously retrieves a {@link CompletableFuture} containing the
     * {@link VaasVerdict} for the given URL.
     * This method uses hash lookup by default.
     *
     * @param url the URL to retrieve the verdict for
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     *         the
     *         URL
     * @throws VaasAuthenticationException If there is an authentication error.
     */
    CompletableFuture<VaasVerdict> forUrlAsync(URL url) throws VaasAuthenticationException;

    /**
     * Asynchronously retrieves a {@link CompletableFuture} containing the
     * {@link VaasVerdict} for the given URL.
     *
     * @param url     the URL to retrieve the verdict for
     * @param options The options to customize the request, such as using hash
     *                lookup.
     * @return a {@link CompletableFuture} containing the {@link VaasVerdict} for
     *         the
     *         URL
     * @throws VaasAuthenticationException If there is an authentication error.
     */
    CompletableFuture<VaasVerdict> forUrlAsync(URL url, ForUrlOptions options) throws VaasAuthenticationException;

    /**
     * Retrieves a {@link VaasVerdict} for the given URL.
     * This method uses hash lookup by default.
     *
     * @param url the URL to retrieve the verdict for
     * @return the {@link VaasVerdict} for the URL
     * @throws InterruptedException        if the thread is interrupted while
     *                                     waiting
     *                                     for the result
     * @throws ExecutionException          if the computation threw an exception
     * @throws VaasAuthenticationException if there is an authentication error
     */
    VaasVerdict forUrl(URL url, ForUrlOptions options)
            throws InterruptedException, ExecutionException, VaasAuthenticationException;

    /**
     * Retrieves a {@link VaasVerdict} for the given URL.
     *
     * @param url     the URL to retrieve the verdict for
     * @param options The options to customize the request, such as using hash
     *                lookup.
     * @return the {@link VaasVerdict} for the URL
     * @throws InterruptedException        if the thread is interrupted while
     *                                     waiting
     *                                     for the result
     * @throws ExecutionException          if the computation threw an exception
     * @throws VaasAuthenticationException if there is an authentication error
     */
    VaasVerdict forUrl(URL url) throws InterruptedException, ExecutionException, VaasAuthenticationException;

}
