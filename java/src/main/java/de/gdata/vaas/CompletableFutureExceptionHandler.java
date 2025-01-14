package de.gdata.vaas;

import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

import de.gdata.vaas.Vaas.ThrowingFunction;

public class CompletableFutureExceptionHandler {
    public static <T, R> Function<T, CompletableFuture<R>> handleException(
            ThrowingFunction<T, CompletableFuture<R>> function) {
        return input -> {
            try {
                return function.apply(input);
            } catch (Exception e) {
                return CompletableFuture.failedFuture(e);
            }
        };
    }
}