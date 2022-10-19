import {expect} from "chai";
import {describe} from "mocha";
import * as dotenv from "dotenv";
import {Vaas} from "../src/Vaas";
import * as randomBytes from "random-bytes";
import {CancellationToken} from "../src/CancellationToken";
import {CreateVaasWithClientCredentialsGrant} from "../src/CreateVaasWithClientCredentialsGrant";
import WebSocket from "isomorphic-ws";
import * as sha256 from "fast-sha256";
import {
    VaasAuthenticationError,
    VaasConnectionClosedError,
    VaasInvalidStateError,
} from "../src/VaasErrors";
import {AuthenticationResponse} from "../src/messages/authentication_response";

const chai = require("chai");
const chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);

function throwError(errorMessage: string): never {
    throw new Error(errorMessage);
}

function getFromEnvironment(key: string) {
    return (
        process.env[key] ?? throwError(`Set ${key} in environment or .env file`)
    );
}

function delay(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

dotenv.config();
const CLIENT_ID = getFromEnvironment("CLIENT_ID");
const CLIENT_SECRET = getFromEnvironment("CLIENT_SECRET");
const VAAS_URL = getFromEnvironment("VAAS_URL");
const TOKEN_URL = getFromEnvironment("TOKEN_URL");

async function createVaas() {
    let vaas = await CreateVaasWithClientCredentialsGrant(
        CLIENT_ID,
        CLIENT_SECRET,
        TOKEN_URL,
        VAAS_URL
    );
    vaas.debug = true;
    return vaas;
}

const defaultTimeout: number = 15_000;

const eicarSha256 =
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const randomFile = randomBytes.sync(50);

describe("Test authentication", function () {
    this.timeout(defaultTimeout);

    it("if wrong authentication token is send, an error is expected", async () => {
        const token = "ThisIsAnInvalidToken";
        const vaas = new Vaas();
        await expect((() => vaas.connect(token))()).to.be.rejectedWith(
            "Vaas authentication failed"
        );
    });
});

describe("Test cancellation through timeout", function () {
    this.timeout(defaultTimeout);

    it("if a request times out, an error is expected", async () => {
        const randomFileContent = randomBytes.sync(50);
        const vaas = await createVaas();
        // 1ms timeout
        const promise = vaas.forFile(
            randomFileContent,
            CancellationToken.fromMilliseconds(1)
        );
        await expect(promise).to.eventually.be.rejectedWith("Timeout");
    });
});

describe("Test verdict requests", function () {
    this.timeout(defaultTimeout);

    it('if a clean SHA256 is submitted, a verdict "clean" is expected', async () => {
        const vaas = await createVaas();
        const verdict = await vaas.forSha256(
            "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23"
        );
        expect(verdict.verdict).to.equal("Clean");
        expect(verdict.sha256.toUpperCase()).to.equal("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23");
    });

    it('if eicar SHA256 is submitted, a verdict "malicious" is expected', async () => {
        const vaas = await createVaas();
        const verdict = await vaas.forSha256(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
        expect(verdict.verdict).to.equal("Malicious");
        expect(verdict.sha256).to.equal("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    });

    it("test if eicar file is detected as malicious based on the SHA256", async () => {
        const eicarString =
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        const eicarByteArray = new TextEncoder().encode(eicarString);
        const vaas = await createVaas();
        const verdict = await vaas.forFile(eicarByteArray);
        expect(verdict.verdict).to.equal("Malicious");
        expect(verdict.sha256).to.equal("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
    });

    it("test if unknown file is uploaded and detected as clean", async () => {
        const randomFileContent = await randomBytes.sync(50);
        var fileSha256 = Vaas.toHexString(sha256.hash(randomFileContent));
        const vaas = await createVaas();
        const verdict = await vaas.forFile(randomFileContent);
        expect(verdict.verdict).to.equal("Clean");
        expect(verdict.sha256).to.equal(fileSha256);
    });

    it("if a list of SHA256 is uploaded, they are detected", async () => {
        const vaas = await createVaas();
        const verdicts = await vaas.forSha256List([
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23",
        ]);
        expect(verdicts[0].verdict).to.equal("Malicious");
        expect(verdicts[0].sha256).to.equal("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
        expect(verdicts[1].verdict).to.equal("Clean");
        expect(verdicts[1].sha256.toUpperCase()).to.equal("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23");
    });

    it("if a list unknown files is uploaded, they are detected as clean", async () => {
        const randomFileContent1 = await randomBytes.sync(50);
        const randomFileContent2 = await randomBytes.sync(50);
        var file1Sha256 = Vaas.toHexString(sha256.hash(randomFileContent1));
        var file2Sha256 = Vaas.toHexString(sha256.hash(randomFileContent2));
        const vaas = await createVaas();
        const verdict = await vaas.forFileList([
            randomFileContent1,
            randomFileContent2,
        ]);
        expect(verdict[0].verdict).to.equal("Clean");
        expect(verdict[0].sha256).to.equal(file1Sha256);
        expect(verdict[1].verdict).to.equal("Clean");
        expect(verdict[1].sha256).to.equal(file2Sha256);
    });

    it("if an empty file is uploaded, it is detected as clean", async () => {
        const emptyFile = new Uint8Array();
        var fileSha256 = Vaas.toHexString(sha256.hash(emptyFile));
        const vaas = await createVaas();
        const verdict = await vaas.forFile(emptyFile);
        expect(verdict.verdict).to.equal("Clean");
        expect(verdict.sha256).to.equal(fileSha256);
    });

    it("if we request the same guid twice, both calls return a result", async () => {
        const vaas = await createVaas();
        const sha256 =
            "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23";
        const request1 = vaas.forSha256(sha256);
        const request2 = vaas.forSha256(sha256);
        const verdict1 = await request1;
        const verdict2 = await request2;
        expect(verdict1.verdict).to.equal("Clean");
        expect(verdict1.sha256.toUpperCase()).to.equal("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23");
        expect(verdict2.verdict).to.equal("Clean");
        expect(verdict2.sha256.toUpperCase()).to.equal("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23");
    });

    xit("keeps connection alive", async () => {
        const vaas = await createVaas();
        const sha256 =
            "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23";
        let verdict = await vaas.forSha256(sha256);
        expect(verdict.verdict).to.equal("Clean");
        await delay(40000);
        verdict = await vaas.forSha256(sha256);
        expect(verdict.verdict).to.equal("Clean");
        expect(verdict.sha256.toUpperCase()).to.equal(sha256);
    }).timeout(45000);

    it("returns Pup for AMTSO pup sample", async () => {
        const vaas = await createVaas();
        const sha256 =
            "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad";
        let verdict = await vaas.forSha256(sha256);
        expect(verdict.verdict).to.equal("Pup");
        expect(verdict.sha256).to.equal(sha256);
    });
});

describe("Vaas", async () => {
    let methodsAndParams: [string, any[]][] = [
        ["forSha256", [eicarSha256]],
        ["forSha256List", [[eicarSha256]]],
        ["forFile", [randomFile]],
        ["forFileList", [[randomFile]]],
    ];

    let webSocket: WebSocket;
    let vaas: Vaas;

    beforeEach(() => {
        webSocket = {
            readyState: WebSocket.CONNECTING as number,
            onopen: () => {
            },
            onclose: () => {
            },
            onmessage: () => {
            },
            send: (data: any) => {
            },
        } as any;
        vaas = new Vaas((url) => webSocket);
    });

    methodsAndParams.forEach(([method, params]) => {
        describe(`#${method}()`, () => {
            it("throws if connect() has not been called", async () => {
                const vaas = new Vaas();
                await expect((vaas as any)[method](...params)).to.be.rejectedWith(
                    VaasInvalidStateError,
                    "connect() was not called"
                );
            });

            it("throws if connect() was not awaited", async () => {
                vaas.connect("token");
                (webSocket as any).readyState = WebSocket.CONNECTING;

                await expect((vaas as any)[method](...params)).to.be.rejectedWith(
                    VaasInvalidStateError,
                    "connect() was not awaited"
                );
            });

            it("throws not authenticated if connect() was not awaited", async () => {
                vaas.connect("token");
                (webSocket as any).readyState = WebSocket.OPEN;

                await expect((vaas as any)[method](...params)).to.be.rejectedWith(
                    VaasInvalidStateError,
                    "Not yet authenticated - connect() was not awaited"
                );
            });

            it("throws if connection was closed", async () => {
                const vaas = await createVaas();
                vaas.close();
                await expect((vaas as any)[method](...params)).to.be.rejectedWith(
                    VaasConnectionClosedError,
                    "Connection was closed"
                );
            });

            it("is rejected if connection is closed by server", async () => {
                const authResponse = new AuthenticationResponse(
                    "sessionId",
                    true,
                    "Authenticated."
                );
                const connected = vaas.connect("token");
                (webSocket as any).readyState = WebSocket.OPEN;
                webSocket.onopen!({} as any);
                webSocket.onmessage!({data: JSON.stringify(authResponse)} as any);
                await connected;
                const promise = (vaas as any)[method](...params);
                webSocket.onclose!({wasClean: true} as any);

                await expect(promise).to.be.rejectedWith(
                    VaasConnectionClosedError,
                    "Connection was closed"
                );
            });

            it("throws if authentication failed", async () => {
                const vaas = new Vaas();
                await expect(vaas.connect("token")).to.be.rejectedWith(
                    VaasAuthenticationError,
                    "Vaas authentication failed"
                );
                await expect((vaas as any)[method](...params)).to.be.rejectedWith(
                    VaasAuthenticationError,
                    "Vaas authentication failed"
                );
            });
        });
    });
});
