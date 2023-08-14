package de.gdata.vaas;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.TemporalUnit;
import java.util.concurrent.TimeUnit;

public class SimpleTimer {

    private final Instant stop;

    public SimpleTimer(long duration, TimeUnit timeUnit) {
        this.stop = Instant.now().plus(duration, timeUnit.toChronoUnit());
    }

    public long getRemainingMs() {
        return Duration.between(Instant.now(), this.stop).toMillis();
    }
}
