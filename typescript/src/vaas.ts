import WebSocket from "isomorphic-ws";
import * as sha256 from "fast-sha256";
import { Kind, Message } from "./messages/message";
import { AuthenticationResponse } from "./messages/authentication_response";
import { AuthenticationRequest } from "./messages/authentication_request";
import { deserialize, serialize } from "typescript-json-serializer";
import { VerdictResponse } from "./messages/verdict_response";
import { WebsocketError } from "./messages/websocket_error";
import { VerdictRequest } from "./messages/verdict_request";
import { v4 as uuidv4 } from "uuid";
import { Verdict } from "./verdict";
import * as axios from "axios";
import { CancellationToken } from "./CancellationToken";

const VAAS_URL = "wss://gateway-vaas.gdatasecurity.de";
export { VAAS_URL };

// See https://advancedweb.hu/how-to-add-timeout-to-a-promise-in-javascript/
const timeout = <T>(promise: Promise<T>, timeoutInMs: number) => {
  let timer: NodeJS.Timeout;
  return Promise.race([
    promise,
    new Promise<never>(
      (_resolve, reject) =>
        (timer = setTimeout(reject, timeoutInMs, new Error("Timeout")))
    ),
  ]).finally(() => clearTimeout(timer));
};

export interface VerdictCallback {
  (verdictResponse: VerdictResponse): Promise<void>;
}

export type VaasConnection = {
  ws: WebSocket;
  sessionId: string;
};

export default class Vaas {
  callbacks: Map<string, VerdictCallback>;
  connection: VaasConnection | null = null;
  defaultTimeoutHashReq: number = 2_000;
  defaultTimeoutFileReq: number = 600_000;
  debug = false;
  pingTimeout?: NodeJS.Timeout;

  constructor() {
    this.callbacks = new Map<string, VerdictCallback>();
  }

  public static toHexString(byteArray: Uint8Array) {
    return Array.from(byteArray, function (byte) {
      return ("0" + (byte & 0xff).toString(16)).slice(-2);
    }).join("");
  }

  public async forSha256(
    sha256: string,
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutHashReq
    )
  ): Promise<Verdict> {
    const request = this.forRequest(sha256).then(
      (response) => response.verdict
    );
    return timeout(request, ct.timeout());
  }

  public async forSha256List(
    sha256List: string[],
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutHashReq
    )
  ): Promise<Verdict[]> {
    const promises = sha256List.map((sha256) => this.forSha256(sha256, ct));
    return Promise.all(promises);
  }

  public async forFile(
    fileBuffer: Uint8Array,
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutFileReq
    )
  ): Promise<Verdict> {
    const request = this.forRequest(fileBuffer).then(
      (response) => response.verdict
    );
    return timeout(request, ct.timeout());
  }

  public async forFileList(
    fileBuffers: Uint8Array[],
    ct: CancellationToken = CancellationToken.fromMilliseconds(
      this.defaultTimeoutFileReq
    )
  ): Promise<Verdict[]> {
    const promises = fileBuffers.map((f) => this.forFile(f, ct));
    return Promise.all(promises);
  }

  public async forRequest(
    sample: string | Uint8Array
  ): Promise<VerdictResponse> {
    return new Promise((resolve, reject) => {
      if (this.connection === null) {
        reject(new Error("Not connected"));
        return;
      }

      const guid = uuidv4();
      if (this.debug) console.debug("uuid", guid);
      this.callbacks.set(guid, async (verdictResponse: VerdictResponse) => {
        if (
          verdictResponse.verdict === Verdict.UNKNOWN &&
          typeof sample !== "string"
        ) {
          await this.upload(verdictResponse, sample);
          return;
        }

        this.callbacks.delete(guid);
        resolve(verdictResponse);
      });

      let hash =
        typeof sample === "string"
          ? sample
          : Vaas.toHexString(sha256.hash(sample));
      const verdictReq = JSON.stringify(
        serialize(new VerdictRequest(hash, guid, this.connection!.sessionId))
      );
      this.connection!.ws.send(verdictReq);
    });
  }

  public async connect(token: string, url = VAAS_URL): Promise<void> {
    return new Promise(async (resolve, reject) => {
      const ws = new WebSocket(url);
      // ws library does not have auto-keepalive
      // https://github.com/websockets/ws/issues/767
      ws.on("ping", (payload) => {
        ws.pong(payload);
      });
      ws.on("pong", async () => {
        this.pingTimeout = setTimeout(() => ws.ping(), 10000);
      });
      ws.onopen = async () => {
        try {
          this.authenticate(ws, token);
        } catch (error) {
          reject(error);
        }
      };
      ws.onerror = (error) => {
        console.log("Error here");
        reject(error);
      };
      ws.onmessage = async (event) => {
        const message = deserialize<Message>(event.data, Message);

        switch (message.kind) {
          case Kind.AuthResponse:
            const authResponse = deserialize<AuthenticationResponse>(
              event.data,
              AuthenticationResponse
            );
            if (authResponse.success) {
              this.connection = { ws: ws, sessionId: authResponse.session_id };
              resolve();
              return;
            }
            reject(new Error("Unauthorized"));
            break;
          case Kind.Error:
            reject(
              deserialize<WebsocketError>(event.data, WebsocketError).text
            );
            break;
          case Kind.VerdictResponse:
            const verdictResponse = deserialize<VerdictResponse>(
              event.data,
              VerdictResponse
            );
            const callback = this.callbacks.get(verdictResponse.guid);
            if (callback) {
              await callback(verdictResponse);
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

  public async upload(
    verdictResponse: VerdictResponse,
    fileBuffer: Uint8Array
  ) {
    return new Promise(async (resolve, reject) => {
      const instance = axios.default.create({
        baseURL: verdictResponse.url,
        // the maximum allowed time for the request
        timeout: 10 * 60 * 1000,
        headers: { Authorization: verdictResponse.upload_token! },
        maxBodyLength: Infinity,
      });
      await instance
        .put("/", fileBuffer)
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
    if (this.pingTimeout) {
      clearTimeout(this.pingTimeout);
      this.pingTimeout = undefined;
    }
    if (this.connection) {
      this.connection.ws.close();
      this.connection = null;
    }
  }

  private authenticate(ws: WebSocket, token: string): void {
    const authReq: string = JSON.stringify(
      serialize(new AuthenticationRequest(token))
    );
    ws.send(authReq);
    ws.ping();
  }
}
