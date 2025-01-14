package de.gdata.vaas.messages;

import lombok.Getter;
import lombok.NonNull;

@Getter
public class VaasVerdict {
    @NonNull
    String sha256;
    @NonNull
    Verdict verdict;
    String detection;
    String fileType;
    String mimeType;

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
