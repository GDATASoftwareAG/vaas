package de.gdata.vaas.messages;

import lombok.Getter;
import lombok.NonNull;

public class VerdictResult {
    @Getter
    @NonNull
    Verdict verdict;
    @Getter
    String uploadUrl;
    @Getter
    String uploadToken;

    public VerdictResult(VerdictResponse verdictResponse) {
        this.uploadUrl = verdictResponse.url;
        this.uploadToken = verdictResponse.uploadToken;
        this.verdict = verdictResponse.verdict;
    }
}
