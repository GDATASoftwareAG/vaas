package de.gdata.vaas;

import lombok.Getter;
import lombok.NonNull;

import java.time.Duration;

public class CancellationTokenSource {

    @Getter
    @NonNull
    public Duration duration;

    public CancellationTokenSource(Duration duration) {
        this.duration = duration;
    }

    public CancellationToken getToken() {
        var ct = new CancellationToken(this.duration);
        ct.start();
        return ct;
    }
}
