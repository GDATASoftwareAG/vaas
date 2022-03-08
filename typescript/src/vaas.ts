import WebSocket from "isomorphic-ws";
import * as sha256 from "fast-sha256";
import { Kind, Message } from "./messages/message";
import { AuthenticationResponse } from "./messages/authentication_response";
import { AuthenticationRequest } from "./messages/authentication_request";
import { deserialize, serialize } from 'typescript-json-serializer';
import { VerdictResponse } from "./messages/verdict_response";
import { WebsocketError } from "./messages/websocket_error";
import { VerdictRequest } from "./messages/verdict_request";
import { v4 as uuidv4 } from 'uuid';
import { Verdict } from "./verdict";
import * as axios from "axios";

export interface VerdictCallback {
    (verdictResponse: VerdictResponse): Promise<void>;
}

export type VaasConnection = {
    ws: WebSocket;
    sessionId: string;
}

export default class Vaas {
    callbacks: Map<string, VerdictCallback>;

    constructor() {
        this.callbacks = new Map<string, VerdictCallback>();
    }

    private static toHexString(byteArray: Uint8Array) {
        return Array.from(byteArray, function (byte) {
            return ('0' + (byte & 0xFF).toString(16)).slice(-2);
        }).join('')
    }

    public async forSha256(vaasConnection: VaasConnection, sha256: string): Promise<Verdict> {
        return new Promise(async (resolve, reject) => {
            const verdictResponse = await this.forRequest(vaasConnection, sha256)
                .catch(error => {
                    reject(error);
                });
            resolve(verdictResponse!.verdict);
        });
    }

    public async forSha256List(vaasConnection: VaasConnection, sha256List: string[]): Promise<Verdict[]> {
        const promises = sha256List.map(sha256 => this.forSha256(vaasConnection, sha256));
        return Promise.all(promises)
    }

    public async forFile(vaasConnection: VaasConnection, fileBuffer: Uint8Array): Promise<Verdict> {
        return new Promise(async (resolve, reject) => {
            const verdictResponse = await this.forRequest(vaasConnection, fileBuffer)
                .catch(error => {
                    reject(error);
                });
            resolve(verdictResponse!.verdict);
        });
    }

    public async forFileList(vaasConnection: VaasConnection, fileBuffers: Uint8Array[]): Promise<Verdict[]> {
        const promises = fileBuffers.map(f => this.forFile(vaasConnection, f));
        return Promise.all(promises);
    }

    public async forRequest(vaasConnection: VaasConnection, sample: string | Uint8Array): Promise<VerdictResponse> {
        return new Promise((resolve, _) => {
            const guid = uuidv4()

            this.callbacks.set(guid, async (verdictResponse: VerdictResponse) => {
                if (typeof sample === "string") {
                    resolve(verdictResponse);
                    this.callbacks.delete(guid);
                    return;
                }
                if (verdictResponse.verdict !== Verdict.UNKNOWN) {
                    resolve(verdictResponse);
                    this.callbacks.delete(guid);
                    return;
                }
                await this.upload(verdictResponse, sample);
            });

            let hash: string;
            if (typeof sample === "string") {
                hash = sample;
            } else {
                hash = Vaas.toHexString(sha256.hash(sample));
            }
            const verdictReq = JSON.stringify(serialize(new VerdictRequest(hash, guid, vaasConnection.sessionId)));
            vaasConnection.ws.send(verdictReq);
        });
    }

    public async connect(token: string): Promise<VaasConnection> {
        return new Promise(async (resolve, reject) => {
            const ws = new WebSocket('wss://gateway-vaas.gdatasecurity.de');
            ws.on("ping", (payload) => {
                ws.pong(payload)
            })
            ws.on("pong", async () => {
                await this.delay(10000);
                ws.ping("ping");
            });
            ws.onopen = async () => {
                try {
                    const vaasCon = await this.authenticate(ws, token);
                    resolve(vaasCon);
                } catch (error) {
                    reject(error);
                }
            };
            ws.onerror = (error) => {
                reject(error.message);
            }
            ws.onmessage = async (event) => {
                const message = deserialize<Message>(event.data, Message);

                switch (message.kind) {
                    case Kind.AuthResponse:
                        const authResponse = deserialize<AuthenticationResponse>(event.data, AuthenticationResponse);
                        if (authResponse.success) {
                            resolve({ ws: ws, sessionId: authResponse.session_id });
                        }
                        reject("Unauthorized");
                        break;
                    case Kind.Error:
                        reject(deserialize<WebsocketError>(event.data, WebsocketError).text);
                        break;
                    case Kind.VerdictResponse:
                        const verdictResponse = deserialize<VerdictResponse>(event.data, VerdictResponse);
                        const callback = this.callbacks.get(verdictResponse.guid);
                        if (callback) {
                            await callback(verdictResponse);
                        }
                        break;
                    default:
                        console.log(event.data);
                        reject("Unknown message kind");
                        break;
                }
            }
        })
    }

    public async upload(verdictResponse: VerdictResponse, fileBuffer: Uint8Array) {
        return new Promise(async (resolve, reject) => {
            const instance = axios.default.create({
                baseURL: verdictResponse.url,
                timeout: 10000,
                headers: { 'Authorization': verdictResponse.upload_token! }
            });
            const response = await instance.put("/", fileBuffer);
            if (response.status != 200) {
                reject(`Upload failed with ${response.status}`);
            }
            resolve(response);
        });

    }

    private delay(ms: number) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private async authenticate(ws: WebSocket, token: string): Promise<VaasConnection> {
        return new Promise((_resolve, _reject) => {
            const authReq: string = JSON.stringify(serialize(new AuthenticationRequest(token)));
            ws.send(authReq);
            ws.ping("ping");
        });
    }
}
