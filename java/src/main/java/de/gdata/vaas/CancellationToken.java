package de.gdata.vaas;

import lombok.Getter;
import lombok.NonNull;
import lombok.SneakyThrows;

import java.time.Duration;

public class CancellationToken extends Thread {

    @NonNull
    private Duration duration;

    @Getter
    public boolean cancelled;

    public boolean isNotCancelled() {
        return !this.cancelled;
    }

    protected CancellationToken(Duration duration) {
        this.duration = duration;
        this.cancelled = false;
    }

    @SneakyThrows
    public void run() {
        Thread.sleep(this.duration.toMillis());
        this.cancelled = true;
    }
}
