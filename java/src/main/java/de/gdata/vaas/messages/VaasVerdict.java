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

    public VaasVerdict(UrlReport urlReport) {
        this.sha256 = urlReport.sha256;
        this.verdict = urlReport.verdict;
        this.detection = urlReport.detection;
        this.fileType = urlReport.fileType;
        this.mimeType = urlReport.mimeType;
    }

    public VaasVerdict(FileReport fileReport) {
        this.sha256 = fileReport.sha256;
        this.verdict = fileReport.verdict;
        this.detection = fileReport.detection;
        this.fileType = fileReport.fileType;
        this.mimeType = fileReport.mimeType;
    }

    public static VaasVerdict From(UrlReport urlReport) {
        return new VaasVerdict(urlReport);
    }

    public static VaasVerdict From(FileReport fileReport) {
        return new VaasVerdict(fileReport);
    }
}
