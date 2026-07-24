import { JsonProperty, JsonObject } from "typescript-json-serializer";
import { Verdict } from "../Verdict";
import { FileReport } from "./FileReport";
import { UrlReport } from "./UrlReport";

@JsonObject()
export class VaasVerdict {
  public constructor(
    @JsonProperty() public sha256: string,
    @JsonProperty() public verdict: Verdict,
    @JsonProperty() public detection: string | undefined,
    @JsonProperty({ name: "fileType" }) public file_type: string | undefined,
    @JsonProperty({ name: "mimeType" }) public mime_type: string | undefined,
    @JsonProperty({ name: "isEncrypted" })
    public is_encrypted: boolean | undefined,
  ) {}

  public static fromFileReport(report: FileReport): VaasVerdict {
    return new VaasVerdict(
      report.sha256,
      report.verdict,
      report.detection,
      report.file_type,
      report.mime_type,
      report.is_encrypted,
    );
  }

  public static fromUrlReport(report: UrlReport): VaasVerdict {
    return new VaasVerdict(
      report.sha256,
      report.verdict,
      report.detection,
      report.file_type,
      report.mime_type,
      report.is_encrypted,
    );
  }
}
