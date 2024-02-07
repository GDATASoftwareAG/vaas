import WebSocket from "isomorphic-ws";
import * as sha256 from "fast-sha256";
import { Kind, Message } from "./messages/message";
import { AuthenticationResponse } from "./messages/authentication_response";
import { AuthenticationRequest } from "./messages/authentication_request";
import { JsonSerializer } from "typescript-json-serializer";
import { VerdictResponse } from "./messages/verdict_response";
import { WebsocketError } from "./messages/websocket_error";
import { VerdictRequest } from "./messages/verdict_request";
import { v4 as uuidv4 } from "uuid";
import { Verdict } from "./Verdict";
import * as axios from "axios";
import { CancellationToken } from "./CancellationToken";
import {
  VaasAuthenticationError,
  VaasConnectionClosedError,
  VaasInvalidStateError,
  VaasServerError,
  VaasTimeoutError,
} from "./VaasErrors";
import { VaasVerdict } from "./messages/vaas_verdict";
import { VerdictRequestForUrl } from "./messages/verdict_request_for_url";
import { ReadStream } from "fs";
import { VerdictRequestForStream } from "./messages/verdict_request_for_stream";
import { Readable } from "stream";

const VAAS_URL = "wss://gateway.production.vaas.gdatasecurity.de";
const defaultSerializer = new JsonSerializer();

export { VAAS_URL };

// See https://advancedweb.hu/how-to-add-timeout-to-a-promise-in-javascript/
const timeout = <T>(promise: Promise<T>, timeoutInMs: number) => {
  let timer: NodeJS.Timeout;
  return Promise.race([
    promise,
    new Promise<never>(
      (_resolve, reject) =>
        (timer = setTimeout(reject, timeoutInMs, new VaasTimeoutError()))
    ),
  ]).finally(() => clearTimeout(timer));
};

export interface VerdictPromise {
  resolve(verdictResponse: VerdictResponse): Promise<void>;
  reject(reason?: any): void;
}

export type VaasConnection = {
  ws: WebSocket;
  sessionId?: string;
};

export class Vaas {
  verdictPromises: Map<string, VerdictPromise>;

  connection: VaasConnection | null = null;
  closeEvent?: WebSocket.CloseEvent;
  authenticationError?: AuthenticationResponse;
  pingTimeout?: NodeJS.Timeout;

  defaultTimeoutHashReq: number = 2_000;
  defaultTimeoutFileReq: number = 600_000;
  defaultTimeoutUrlReq: number = 600_000;
  defaultTimeoutStreamReq: number = 100_000;
  debug = false;

  constructor(private webSocketFactory = (url: string) => new WebSocket(url)) {
    this.verdictPromises = new Map<string, VerdictPromise>();
  }

  public static toHexString(byteArray: Uint8Array) {
    return Array.from(byteArray, function (byte) {
      return ("0" + (byte & 0xff).toString(16)).slice(-2);
    }).join("");
  }

  /** Get verdict for InputStream
   * @throws {VaasInvalidStateError} If connect() has not been called and awaited. Signifies caller error.
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasConnectionClosedError} Connection was closed. Call connect() to reconnect.
   * @throws {VaasTimeoutError} Timeout. Retry request.
   */
  public async forStream(
    stream: Readable,
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutStreamReq
    )
  ): Promise<VaasVerdict> {
    const request = this.forStreamRequest(stream).then(
      (response) => response
    );
    return timeout(request, ct.timeout());
  }  

  /** Get verdict for URL
   * @throws {VaasInvalidStateError} If connect() has not been called and awaited. Signifies caller error.
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasConnectionClosedError} Connection was closed. Call connect() to reconnect.
   * @throws {VaasTimeoutError} Timeout. Retry request.
   */
   public async forUrl(
    url: URL,
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutUrlReq
    )
  ): Promise<VaasVerdict> {
    const request = this.forUrlRequest(url).then(
      (response) => response
    );
    return timeout(request, ct.timeout());
  }

  /** Get verdict for a SHA256
   * @throws {VaasInvalidStateError} If connect() has not been called and awaited. Signifies caller error.
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasConnectionClosedError} Connection was closed. Call connect() to reconnect.
   * @throws {VaasTimeoutError} Timeout. Retry request.
   */
  public async forSha256(
    sha256: string,
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutHashReq
    )
  ): Promise<VaasVerdict> {
    const request = this.forRequest(sha256).then(
      (response) => response
    );
    return timeout(request, ct.timeout());
  }

  /** Get verdict for list of SHA256
   * @throws {VaasInvalidStateError} If connect() has not been called and awaited. Signifies caller error.
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasConnectionClosedError} Connection was closed. Call connect() to reconnect.
   * @throws {VaasTimeoutError} Timeout. Retry request.
   */
  public async forSha256List(
    sha256List: string[],
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutHashReq
    )
  ): Promise<VaasVerdict[]> {
    const promises = sha256List.map((sha256) => this.forSha256(sha256, ct));
    return Promise.all(promises);
  }

  /** Get verdict for a file
   * @throws {VaasInvalidStateError} If connect() has not been called and awaited. Signifies caller error.
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasConnectionClosedError} Connection was closed. Call connect() to reconnect.
   * @throws {VaasTimeoutError} Timeout. Retry request.
   */
  public async forFile(
    fileBuffer: Uint8Array,
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutFileReq
    )
  ): Promise<VaasVerdict> {
    const request = this.forRequest(fileBuffer).then(
      (response) => response
    );
    return timeout(request, ct.timeout());
  }

  /** Get verdict for a list of files
   * @throws {VaasInvalidStateError} If connect() has not been called and awaited. Signifies caller error.
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasConnectionClosedError} Connection was closed. Call connect() to reconnect.
   * @throws {VaasTimeoutError} Timeout. Retry request.
   */
  public async forFileList(
    fileBuffers: Uint8Array[],
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutFileReq
    )
  ): Promise<VaasVerdict[]> {
    const promises = fileBuffers.map((f) => this.forFile(f, ct));
    return Promise.all(promises);
  }

  private async forRequest(
    sample: string | Uint8Array
  ): Promise<VaasVerdict> {
    const ws = this.getAuthenticatedWebSocket();
    return new Promise((resolve, reject) => {
      const guid = uuidv4();
      if (this.debug) console.debug("uuid", guid);
      this.verdictPromises.set(guid, {
        resolve: async (verdictResponse: VerdictResponse) => {
          if (
            verdictResponse.verdict === Verdict.UNKNOWN &&
            typeof sample !== "string"
          ) {
            await this.upload(verdictResponse, sample);
            return;
          }

          this.verdictPromises.delete(guid);
          resolve(new VaasVerdict(verdictResponse.sha256, verdictResponse.verdict));
        },
        reject: (reason) => reject(reason),
      });

      let hash =
        typeof sample === "string"
          ? sample
          : Vaas.toHexString(sha256.hash(sample));
      const verdictReq = JSON.stringify(
        defaultSerializer.serialize(
          new VerdictRequest(hash, guid, this.connection!.sessionId as string)
        )
      );
      ws.send(verdictReq);
    });
  }

  private async forUrlRequest(
    url: URL
  ): Promise<VaasVerdict> {
    const ws = this.getAuthenticatedWebSocket();
    return new Promise((resolve, reject) => {
      const guid = uuidv4();
      if (this.debug) console.debug("uuid", guid);
      this.verdictPromises.set(guid, {
        resolve: async (verdictResponse: VerdictResponse) => {
          this.verdictPromises.delete(guid);
          resolve(new VaasVerdict(verdictResponse.sha256, verdictResponse.verdict));
        },
        reject: (reason) => reject(reason),
      });

    
      const verdictReq = JSON.stringify(
        defaultSerializer.serialize(
          new VerdictRequestForUrl(url, guid, this.connection!.sessionId as string)
        )
      );
      ws.send(verdictReq);
    });
  }

  private async forStreamRequest(
    stream: Readable
  ): Promise<VaasVerdict> {
    const ws = this.getAuthenticatedWebSocket();
    return new Promise((resolve, reject) => {
      const guid = uuidv4();
      if (this.debug) console.debug("uuid", guid);
      this.verdictPromises.set(guid, {
        resolve: async (verdictResponse: VerdictResponse) => {
          if (verdictResponse.verdict !== Verdict.UNKNOWN) {
            throw new VaasServerError("Server returned verdict without receiving content");
          }
          const contentLength = stream.readableLength;
          await this.upload(verdictResponse, stream, contentLength);
          this.verdictPromises.delete(guid);
          resolve(new VaasVerdict(verdictResponse.sha256, verdictResponse.verdict));
        },
        reject: (reason) => reject(reason),
      });

      const verdictReq = JSON.stringify(
        defaultSerializer.serialize(
          new VerdictRequestForStream(guid, this.connection!.sessionId as string)
        )
      );
      ws.send(verdictReq);
    });
  }
  
  /** Connect to VaaS
   * @throws {VaasAuthenticationError} Authentication failed.
   * @throws {VaasConnectionClosedError} Connection was closed. Call connect() to reconnect.
   */
  public connect(token: string, url = VAAS_URL): Promise<void> {
    return new Promise((resolve, reject) => {
      const ws = this.webSocketFactory(url);
      this.connection = { ws: ws };
      this.closeEvent = undefined;
      this.authenticationError = undefined;
      this.pingTimeout = undefined;

      // ws library does not have auto-keepalive
      // https://github.com/websockets/ws/issues/767
      if (ws.on !== undefined) {
        ws.on("ping", (payload) => {
          ws.pong(payload);
        });
        ws.on("pong", () => {
          this.pingTimeout = setTimeout(() => ws.ping(), 10000);
        });
      }
      ws.onopen = () => {
        try {
          this.authenticate(token);
        } catch (error) {
          reject(error);
        }
      };
      ws.onclose = (event) => {
        if (this.pingTimeout) {
          clearTimeout(this.pingTimeout);
          this.pingTimeout = undefined;
        }
        if (!event.wasClean) {
          this.closeEvent = event;
        }
        const reason = new VaasConnectionClosedError(event);
        if (this.verdictPromises.size > 0) {
          this.verdictPromises.forEach((c) => c.reject(reason));
          this.verdictPromises.clear();
        }
        reject(reason);
      };
      ws.onmessage = async (event) => {
        const message = defaultSerializer.deserializeObject(event.data, Message) as Message;

        switch (message.kind) {
          case Kind.AuthResponse:
            const authResponse = defaultSerializer.deserializeObject(
              event.data,
              AuthenticationResponse
            ) as AuthenticationResponse;
            if (authResponse.success) {
              this.connection!.sessionId = authResponse.session_id;
              resolve();
              return;
            }
            this.authenticationError = authResponse;
            reject(new VaasAuthenticationError());
            break;
          case Kind.Error:
            reject(
              (defaultSerializer.deserialize(event.data, WebsocketError) as WebsocketError).text
            );
            break;
          case Kind.VerdictResponse:
            const verdictResponse = defaultSerializer.deserialize(
              event.data,
              VerdictResponse
            ) as VerdictResponse;
            const promise = this.verdictPromises.get(verdictResponse.guid);
            if (promise) {
              await promise.resolve(verdictResponse);
            }
            break;
          default:
            console.log(event.data);
            reject(new Error("Unknown message kind"));
            break;
        }
      };
    });
  }

  private async upload(
    verdictResponse: VerdictResponse,
    input: Uint8Array | Readable,
    contentLength: number = Infinity
  ) {
    return new Promise(async (resolve, reject) => {
      const instance = axios.default.create({
        baseURL: verdictResponse.url,
        // the maximum allowed time for the request
        timeout: 10 * 60 * 1000,
        headers: {
          Authorization: verdictResponse.upload_token!,
          "Content-Type": "application/octet-stream"
        },
        maxBodyLength: contentLength,
      });
      await instance
        .put("/", input)
        .then((response) => resolve(response))
        .catch((error) => {
          if (error instanceof axios.AxiosError && error.response) {
            reject(
              new Error(
                `Upload failed with ${error.response.status} - Error ${error.response.data.message}`
              )
            );
          } else {
            throw error;
          }
        });
    });
  }

  public close() {
    if (this.connection) {
      this.connection.ws.close();
      this.authenticationError = undefined;
    }
  }

  private authenticate(token: string): void {
    const authReq: string = JSON.stringify(
      defaultSerializer.serialize(new AuthenticationRequest(token))
    );
    const ws = this.getConnectedWebSocket();
    ws.send(authReq);
    if (ws.ping !== undefined) {
      ws.ping();
    }
  }

  private getConnectedWebSocket() {
    const ws = this.connection?.ws;
    if (!ws) {
      throw new VaasInvalidStateError("connect() was not called");
    }
    if (ws.readyState === WebSocket.CONNECTING) {
      throw new VaasInvalidStateError("connect() was not awaited");
    }
    if (ws.readyState !== WebSocket.OPEN) {
      throw new VaasConnectionClosedError(this.closeEvent);
    }
    return ws;
  }

  private getAuthenticatedWebSocket() {
    const ws = this.getConnectedWebSocket();
    if (!this.connection?.sessionId) {
      if (this.authenticationError) throw new VaasAuthenticationError();
      throw new VaasInvalidStateError(
        "Not yet authenticated - connect() was not awaited"
      );
    }
    return ws;
  }
}
