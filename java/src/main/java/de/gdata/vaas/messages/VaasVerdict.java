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
    String detection;
    @Getter
    String fileType;
    @Getter
    String mimeType;

    public VaasVerdict(VerdictResponse verdictResponse) {
        this.sha256 = verdictResponse.sha256;
        this.verdict = verdictResponse.verdict;
        this.detection = verdictResponse.detection;
        this.fileType = verdictResponse.fileType;
        this.mimeType = verdictResponse.mimeType;
    }
}
