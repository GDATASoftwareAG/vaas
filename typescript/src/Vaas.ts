import * as sha256 from "fast-sha256";
import axios, { AxiosInstance } from "axios";
import { Readable } from "stream";
import { CancellationToken } from "./CancellationToken";
import {
  VaasAuthenticationError,
  VaasClientError,
  VaasServerError,
  VaasTimeoutError,
} from "./VaasErrors";
import { VaasVerdict } from "./messages/vaas_verdict";
import { FileReport } from "./messages/FileReport";
import { FileAnalysisStarted } from "./messages/FileAnalysisStarted";
import { UrlAnalysisRequest } from "./messages/UrlAnalysisRequest";
import { UrlAnalysisStarted } from "./messages/UrlAnalysisStarted";
import { UrlReport } from "./messages/UrlReport";
import { ProblemDetails } from "./messages/ProblemDetails";
import { VaasOptions } from "./options/VaasOptions";
import { ForSha256Options } from "./options/ForSha256Options";
import { ForFileOptions } from "./options/ForFileOptions";
import { ForStreamOptions } from "./options/ForStreamOptions";
import { ForUrlOptions } from "./options/ForUrlOptions";
import { JsonSerializer } from "typescript-json-serializer";

const defaultSerializer = new JsonSerializer();

const VAAS_URL = "https://gateway.production.vaas.gdatasecurity.de";
const USER_AGENT = `gdata-vaas-typescript/${require("../package.json").version}`;

export { VAAS_URL };

const timeout = <T>(promise: Promise<T>, timeoutInMs: number) => {
  let timer: NodeJS.Timeout;
  return Promise.race([
    promise,
    new Promise<never>(
      (_resolve, reject) =>
        (timer = setTimeout(reject, timeoutInMs, new VaasTimeoutError())),
    ),
  ]).finally(() => clearTimeout(timer));
};

export interface Authenticator {
  getToken(): Promise<string>;
}

export class Vaas {
  private options: VaasOptions;
  private httpClient: AxiosInstance;

  defaultTimeoutHashReq: number = 2_000;
  defaultTimeoutFileReq: number = 600_000;
  defaultTimeoutUrlReq: number = 600_000;
  defaultTimeoutStreamReq: number = 100_000;
  debug = false;

  constructor(
    private authenticator: Authenticator,
    options?: VaasOptions,
    httpClient?: AxiosInstance,
  ) {
    this.options = options ?? new VaasOptions();
    this.httpClient =
      httpClient ??
      axios.create({
        timeout: this.options.timeout,
        validateStatus: () => true,
      });
  }

  public static toHexString(byteArray: Uint8Array): string {
    return Array.from(byteArray, function (byte) {
      return ("0" + (byte & 0xff).toString(16)).slice(-2);
    }).join("");
  }

  private getBaseUrl(): string {
    return (
      this.httpClient.defaults.baseURL ?? this.options.vaasUrl ?? VAAS_URL
    );
  }

  /** Get verdict for Readable Stream
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasClientError} The request is malformed or cannot be completed.
   * @throws {VaasServerError} The server encountered an internal error.
   * @throws {VaasTimeoutError} Timeout. Retry request.
   */
  public async forStream(
    stream: Readable,
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutStreamReq,
    ),
    options?: ForStreamOptions,
  ): Promise<VaasVerdict> {
    const request = this.forStreamRequest(
      stream,
      options ?? ForStreamOptions.from(this.options),
    ).then((response) => response);
    return timeout(request, ct.timeout());
  }

  /** Get verdict for URL
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasClientError} The request is malformed or cannot be completed.
   * @throws {VaasServerError} The server encountered an internal error.
   * @throws {VaasTimeoutError} Timeout. Retry request.
   */
  public async forUrl(
    url: URL,
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutUrlReq,
    ),
    options?: ForUrlOptions,
  ): Promise<VaasVerdict> {
    const request = this.forUrlRequest(
      url,
      options ?? ForUrlOptions.from(this.options),
    ).then((response) => response);
    return timeout(request, ct.timeout());
  }

  /** Get verdict for a SHA256
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasClientError} The request is malformed or cannot be completed.
   * @throws {VaasServerError} The server encountered an internal error.
   * @throws {VaasTimeoutError} Timeout. Retry request.
   */
  public async forSha256(
    sha256: string,
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutHashReq,
    ),
    options?: ForSha256Options,
  ): Promise<VaasVerdict> {
    const request = this.forSha256Request(
      sha256,
      options ?? ForSha256Options.from(this.options),
    ).then((response) => response);
    return timeout(request, ct.timeout());
  }

  /** Get verdict for list of SHA256
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasClientError} The request is malformed or cannot be completed.
   * @throws {VaasServerError} The server encountered an internal error.
   * @throws {VaasTimeoutError} Timeout. Retry request.
   */
  public async forSha256List(
    sha256List: string[],
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutHashReq,
    ),
  ): Promise<VaasVerdict[]> {
    const promises = sha256List.map((sha256) => this.forSha256(sha256, ct));
    return Promise.all(promises);
  }

  /** Get verdict for a file
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasClientError} The request is malformed or cannot be completed.
   * @throws {VaasServerError} The server encountered an internal error.
   * @throws {VaasTimeoutError} Timeout. Retry request.
   */
  public async forFile(
    fileBuffer: Uint8Array,
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutFileReq,
    ),
    options?: ForFileOptions,
  ): Promise<VaasVerdict> {
    const request = this.forFileRequest(
      fileBuffer,
      options ?? ForFileOptions.from(this.options),
    ).then((response) => response);
    return timeout(request, ct.timeout());
  }

  /** Get verdict for a list of files
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasClientError} The request is malformed or cannot be completed.
   * @throws {VaasServerError} The server encountered an internal error.
   * @throws {VaasTimeoutError} Timeout. Retry request.
   */
  public async forFileList(
    fileBuffers: Uint8Array[],
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutFileReq,
    ),
  ): Promise<VaasVerdict[]> {
    const promises = fileBuffers.map((f) => this.forFile(f, ct));
    return Promise.all(promises);
  }

  private async forSha256Request(
    sha256: string,
    options: ForSha256Options,
  ): Promise<VaasVerdict> {
    const reportUrl = new URL(`/files/${sha256}/report`, this.getBaseUrl());
    reportUrl.searchParams.set("useCache", String(options.useCache));
    reportUrl.searchParams.set("useHashLookup", String(options.useHashLookup));

    while (true) {
      const response = await this.httpClient.get(reportUrl.toString(), {
        headers: await this.getHeaders(options.vaasRequestId),
      });

      this.raiseIfVaasErrorOccurred(response);

      if (response.status === 200) {
        const report = defaultSerializer.deserializeObject(
          response.data,
          FileReport,
        ) as FileReport;
        return VaasVerdict.fromFileReport(report);
      }
      if (response.status === 202) {
        continue;
      }

      throw new VaasServerError(
        `Unexpected status code ${response.status}: ${response.statusText}`,
      );
    }
  }

  private async forFileRequest(
    fileBuffer: Uint8Array,
    options: ForFileOptions,
  ): Promise<VaasVerdict> {
    if (options.useCache || options.useHashLookup) {
      const hash = Vaas.toHexString(sha256.hash(fileBuffer));
      const forSha256Options = new ForSha256Options({
        useCache: options.useCache,
        useHashLookup: options.useHashLookup,
        vaasRequestId: options.vaasRequestId,
      });

      try {
        const verdict = await this.forSha256Request(hash, forSha256Options);
        const verdictWithoutDetection =
          (verdict.verdict === "Malicious" || verdict.verdict === "Pup") &&
          verdict.detection === undefined;
        if (
          verdict.verdict !== "Unknown" &&
          !verdictWithoutDetection &&
          verdict.file_type !== undefined &&
          verdict.mime_type !== undefined
        ) {
          return verdict;
        }
      } catch {
        // ignore and upload
      }
    }

    const forStreamOptions = new ForStreamOptions({
      useHashLookup: options.useHashLookup,
      vaasRequestId: options.vaasRequestId,
    });
    return this.forStreamRequest(
      Readable.from([fileBuffer]),
      forStreamOptions,
      fileBuffer.length,
    );
  }

  private async forStreamRequest(
    stream: Readable,
    options: ForStreamOptions,
    contentLength?: number,
  ): Promise<VaasVerdict> {
    const uploadUrl = new URL("/files", this.getBaseUrl());
    uploadUrl.searchParams.set("useCache", "true");
    uploadUrl.searchParams.set("useHashLookup", String(options.useHashLookup));

    const headers = await this.getHeaders(options.vaasRequestId);
    if (contentLength !== undefined) {
      headers["Content-Length"] = String(contentLength);
    }

    const response = await this.httpClient.post(uploadUrl.toString(), stream, {
      headers,
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
    });

    this.raiseIfVaasErrorOccurred(response);

    if (response.status !== 200 && response.status !== 201) {
      throw new VaasServerError(
        `Unexpected status code ${response.status}: ${response.statusText}`,
      );
    }

    const analysisStarted = defaultSerializer.deserializeObject(
      response.data,
      FileAnalysisStarted,
    ) as FileAnalysisStarted;
    const forSha256Options = new ForSha256Options({
      useHashLookup: options.useHashLookup,
      vaasRequestId: options.vaasRequestId,
    });
    return this.forSha256Request(analysisStarted.sha256, forSha256Options);
  }

  private async forUrlRequest(
    url: URL,
    options: ForUrlOptions,
  ): Promise<VaasVerdict> {
    const urlAnalysisUri = new URL("/urls", this.getBaseUrl());

    const request = new UrlAnalysisRequest(url.toString(), options.useHashLookup);
    const headers = await this.getHeaders(options.vaasRequestId);
    headers["Content-Type"] = "application/json";

    const response = await this.httpClient.post(
      urlAnalysisUri.toString(),
      JSON.stringify(request),
      { headers },
    );

    this.raiseIfVaasErrorOccurred(response);

    if (response.status !== 200 && response.status !== 201) {
      throw new VaasServerError(
        `Unexpected status code ${response.status}: ${response.statusText}`,
      );
    }

    const analysisStarted = defaultSerializer.deserializeObject(
      response.data,
      UrlAnalysisStarted,
    ) as UrlAnalysisStarted;
    const reportUrl = new URL(
      `/urls/${analysisStarted.id}/report`,
      this.getBaseUrl(),
    );

    while (true) {
      const reportResponse = await this.httpClient.get(reportUrl.toString(), {
        headers: await this.getHeaders(options.vaasRequestId),
      });

      this.raiseIfVaasErrorOccurred(reportResponse);

      if (reportResponse.status === 200) {
        const report = defaultSerializer.deserializeObject(
          reportResponse.data,
          UrlReport,
        ) as UrlReport;
        return VaasVerdict.fromUrlReport(report);
      }
      if (reportResponse.status === 202) {
        continue;
      }

      throw new VaasServerError(
        `Unexpected status code ${reportResponse.status}: ${reportResponse.statusText}`,
      );
    }
  }

  private async getHeaders(
    vaasRequestId?: string,
  ): Promise<Record<string, string>> {
    const token = await this.authenticator.getToken();
    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      "User-Agent": USER_AGENT,
    };
    if (vaasRequestId) {
      headers["tracestate"] = `vaasrequestid=${vaasRequestId}`;
    }
    return headers;
  }

  private raiseIfVaasErrorOccurred(response: {
    status: number;
    statusText: string;
    data: unknown;
  }): void {
    if (response.status < 200 || response.status >= 300) {
      const problemDetails = this.tryParseProblemDetails(response.data);
      if (problemDetails) {
        if (response.status === 401) {
          throw new VaasAuthenticationError(problemDetails.detail);
        }
        if (problemDetails.type === "VaasClientException") {
          throw new VaasClientError(problemDetails);
        }
        throw new VaasServerError(problemDetails);
      }

      if (response.status === 401) {
        throw new VaasAuthenticationError();
      }
      if (response.status >= 400 && response.status < 500) {
        throw new VaasClientError(
          `HTTP Error ${response.status}: ${response.statusText}`,
        );
      }
      throw new VaasServerError(
        `HTTP Error ${response.status}: ${response.statusText}`,
      );
    }
  }

  private tryParseProblemDetails(data: unknown): ProblemDetails | undefined {
    if (
      typeof data === "object" &&
      data !== null &&
      "type" in data &&
      "detail" in data &&
      typeof (data as { type: unknown }).type === "string" &&
      typeof (data as { detail: unknown }).detail === "string"
    ) {
      return new ProblemDetails(
        (data as { type: string }).type,
        (data as { detail: string }).detail,
      );
    }
    return undefined;
  }
}
