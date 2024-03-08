package de.gdata.vaas.messages;

import lombok.Getter;
import lombok.NonNull;

import java.util.ArrayList;

public class VaasVerdict {
    @Getter
    @NonNull
    String sha256;
    @Getter
    @NonNull
    Verdict verdict;
    @Getter
    ArrayList<Detection> detections;
    @Getter
    LibMagic libMagic;

    public VaasVerdict(VerdictResponse verdictResponse) {
        this.sha256 = verdictResponse.sha256;
        this.verdict = verdictResponse.verdict;
        this.detections = verdictResponse.detections;
        this.libMagic = verdictResponse.libMagic;
    }
}
