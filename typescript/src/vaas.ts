import WebSocket from "isomorphic-ws";
import * as sha256 from "fast-sha256";
import {Kind, Message} from "./messages/message";
import {AuthenticationResponse} from "./messages/authentication_response";
import {AuthenticationRequest} from "./messages/authentication_request";
import {deserialize, serialize} from 'typescript-json-serializer';
import {VerdictResponse} from "./messages/verdict_response";
import {WebsocketError} from "./messages/websocket_error";
import {VerdictRequest} from "./messages/verdict_request";
import {v4 as uuidv4} from 'uuid';
import {Verdict} from "./verdict";
import * as axios from "axios";

export interface VerdictCallback {
    (result: Result): void;
}

export type Result = Verdict | string;

export type VaasConnection = {
    ws: WebSocket;
    sessionId: string;
}

export class Vaas {

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

    public async forRequest(vaasConnection: VaasConnection, sample: string | Uint8Array): Promise<VerdictResponse> {
        return new Promise((resolve, reject) => {
            const guid = uuidv4()

            vaasConnection.ws.onmessage = async (event) => {
                const message = deserialize<Message>(event.data, Message);

                switch (message.kind) {
                    case Kind.Error:
                        reject(deserialize<WebsocketError>(event.data, WebsocketError).text);
                        break;
                    case Kind.VerdictResponse:
                        const verdictResponse = deserialize<VerdictResponse>(event.data, VerdictResponse);
                        if (typeof sample === "string") {
                            resolve(verdictResponse);
                            return;
                        }
                        if (verdictResponse.verdict !== Verdict.UNKNOWN) {
                            resolve(verdictResponse);
                            return;
                        }
                        await this.upload(verdictResponse, sample);
                        return;
                    default:
                        console.log(event.data);
                        reject("Unknown message kind");
                        return;
                }
            }

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
        })
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

    public async upload(verdictResponse: VerdictResponse, fileBuffer: Uint8Array) {
        return new Promise(async (resolve, reject) => {
            const instance = axios.default.create({
                baseURL: verdictResponse.url,
                timeout: 10000,
                headers: {'Authorization': verdictResponse.upload_token!}
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
        return new Promise((resolve, reject) => {
            const authReq: string = JSON.stringify(serialize(new AuthenticationRequest(token)));
            ws.send(authReq);
            ws.once("message", (data) => {
                const authResponse = deserialize<AuthenticationResponse>(data.toString(), AuthenticationResponse);
                if (authResponse.success) {
                    resolve({ws: ws, sessionId: authResponse.session_id});
                }
                reject("Unauthorized");
            });
            ws.ping("ping");
        });
    }
}