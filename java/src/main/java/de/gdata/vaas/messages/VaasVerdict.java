package de.gdata.vaas.messages;

import lombok.Getter;
import lombok.NonNull;

public class VaasVerdict {
    @Getter
    @NonNull
    String sha256;
    @Getter
    @NonNull
    Verdict verdict;

    public VaasVerdict(VerdictResponse verdictResponse) {
        this.sha256 = verdictResponse.sha256;
        this.verdict = verdictResponse.verdict;
    }
}
