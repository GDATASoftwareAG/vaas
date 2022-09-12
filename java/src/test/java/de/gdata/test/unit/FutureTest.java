package de.gdata.test.unit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class FutureTest {
    @Test
    public void get_timeout() {
        var f = new CompletableFuture<String>();
        assertThrows(TimeoutException.class, () -> f.get(1, TimeUnit.MILLISECONDS));
    }

    @Test
    public void get_cancelFalse() {
        var f = new CompletableFuture<String>();
        f.cancel(false);
        assertThrows(CancellationException.class, () -> f.get());
    }

    @Test
    public void get_cancelTrue() {
        var f = new CompletableFuture<String>();
        var thread = new Thread(() -> this.runGet(f));
        thread.start();
        f.cancel(true);
        assertDoesNotThrow(() -> thread.join());
    }

    @Test
    public void get_interrupted() {
        var f = new CompletableFuture<String>();
        var thread = new Thread(() -> this.runGet(f));
        thread.start();
        thread.interrupt();
        assertDoesNotThrow(() -> thread.join());
    }

    private void runGet(Future<String> f) {
        try {
            f.get();
        } catch (InterruptedException | ExecutionException e) {
        }
    }
}
