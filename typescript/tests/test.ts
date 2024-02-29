import { expect } from "chai";
import { describe } from "mocha";
import * as dotenv from "dotenv";
import { Vaas } from "../src/Vaas";
import * as randomBytes from "random-bytes";
import { CancellationToken } from "../src/CancellationToken";
import WebSocket from "isomorphic-ws";
import * as sha256 from "fast-sha256";
import {
  VaasAuthenticationError,
  VaasConnectionClosedError,
  VaasInvalidStateError,
} from "../src/VaasErrors";
import ClientCredentialsGrantAuthenticator from "../src/ClientCredentialsGrantAuthenticator";
import ResourceOwnerPasswordGrantAuthenticator from "../src/ResourceOwnerPasswordGrantAuthenticator";
import { Readable } from "stream";
import axios, { AxiosResponse } from "axios";

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
const VAAS_USER_NAME = getFromEnvironment("VAAS_USER_NAME");
const VAAS_PASSWORD = getFromEnvironment("VAAS_PASSWORD");
const VAAS_CLIENT_ID = getFromEnvironment("VAAS_CLIENT_ID");

async function createVaasWithClientCredentialsGrantAuthenticator() {
  let authenticator = new ClientCredentialsGrantAuthenticator(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL,
  );
  let vaas = new Vaas();
  let token = await authenticator.getToken();
  await vaas.connect(token, VAAS_URL);
  vaas.debug = true;
  return vaas;
}

async function createVaasWithResourceOwnerPasswordGrantAuthenticator() {
  let authenticator = new ResourceOwnerPasswordGrantAuthenticator(
    VAAS_CLIENT_ID,
    VAAS_USER_NAME,
    VAAS_PASSWORD,
    TOKEN_URL,
  );
  let vaas = new Vaas();
  let token = await authenticator.getToken();
  await vaas.connect(token, VAAS_URL);
  vaas.debug = true;
  return vaas;
}

const defaultTimeout: number = 130_000;

const eicarSha256 =
  "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const randomFile = randomBytes.sync(50);

describe("Test authentication", function () {
  this.timeout(defaultTimeout);

  it("if wrong authentication token is send, an error is expected", async () => {
    const token = "ThisIsAnInvalidToken";
    const vaas = new Vaas();
    await expect(
      (async () => await vaas.connect(token, VAAS_URL))(),
    ).to.be.rejectedWith("Vaas authentication failed");
  });
});

describe("Test authentication with ResourceOwnerPasswordGrantAuthenticator", function () {
  this.timeout(defaultTimeout);

  it("if a request times out, an error is expected", async () => {
    const vaas = await createVaasWithResourceOwnerPasswordGrantAuthenticator();
    const verdict = await vaas.forSha256(
      "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C",
    );
    expect(verdict.verdict).to.equal("Clean");
  });
});

describe("Test cancellation through timeout", function () {
  this.timeout(defaultTimeout);

  it("if a request times out, an error is expected", async () => {
    const randomFileContent = randomBytes.sync(50);
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    // 1ms timeout
    const promise = vaas.forFile(
      randomFileContent,
      CancellationToken.fromMilliseconds(1),
    );
    await expect(promise).to.eventually.be.rejectedWith("Timeout");
  });
});

describe("Test verdict requests", function () {
  this.timeout(defaultTimeout);

  it('if a clean SHA256 is submitted, a verdict "clean" is expected', async () => {
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const verdict = await vaas.forSha256(
      "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C",
    );
    expect(verdict.verdict).to.equal("Clean");
    expect(verdict.sha256.toUpperCase()).to.equal(
      "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C",
    );
  });

  it('if eicar SHA256 is submitted, a verdict "malicious" is expected', async () => {
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const verdict = await vaas.forSha256(
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    );
    expect(verdict.verdict).to.equal("Malicious");
    expect(verdict.sha256).to.equal(
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    );
  });

  it("test if eicar file is detected as malicious based on the SHA256", async () => {
    const eicarString =
      "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const eicarByteArray = new TextEncoder().encode(eicarString);
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const verdict = await vaas.forFile(eicarByteArray);
    expect(verdict.verdict).to.equal("Malicious");
    expect(verdict.sha256).to.equal(
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    );
  });

  it("test if unknown file is uploaded and detected as clean", async () => {
    const randomFileContent = await randomBytes.sync(50);
    var fileSha256 = Vaas.toHexString(sha256.hash(randomFileContent));
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const verdict = await vaas.forFile(randomFileContent);
    expect(verdict.verdict).to.equal("Clean");
    expect(verdict.sha256).to.equal(fileSha256);
  });

  it("if a list of SHA256 is uploaded, they are detected", async () => {
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const verdicts = await vaas.forSha256List([
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C",
    ]);
    expect(verdicts[0].verdict).to.equal("Malicious");
    expect(verdicts[0].sha256).to.equal(
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    );
    expect(verdicts[1].verdict).to.equal("Clean");
    expect(verdicts[1].sha256.toUpperCase()).to.equal(
      "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C",
    );
  });

  it("if a list unknown files is uploaded, they are detected as clean", async () => {
    const randomFileContent1 = await randomBytes.sync(50);
    const randomFileContent2 = await randomBytes.sync(50);
    var file1Sha256 = Vaas.toHexString(sha256.hash(randomFileContent1));
    var file2Sha256 = Vaas.toHexString(sha256.hash(randomFileContent2));
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
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
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const verdict = await vaas.forFile(emptyFile);
    expect(verdict.verdict).to.equal("Clean");
    expect(verdict.sha256).to.equal(fileSha256);
  });

  it("if we request the same guid twice, both calls return a result", async () => {
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const sha256 =
      "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C";
    const request1 = vaas.forSha256(sha256);
    const request2 = vaas.forSha256(sha256);
    const verdict1 = await request1;
    const verdict2 = await request2;
    expect(verdict1.verdict).to.equal("Clean");
    expect(verdict1.sha256.toUpperCase()).to.equal(
      "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C",
    );
    expect(verdict2.verdict).to.equal("Clean");
    expect(verdict2.sha256.toUpperCase()).to.equal(
      "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C",
    );
  });
  //www.virustotal.com/gui/file/edb6991d68ba5c7ed43f198c3d2593c770f2634beeb8c83afe3138279e5e81f3
  https: xit("keeps connection alive", async () => {
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const sha256 =
      "3A78F382E8E2968EC201B33178102E06DB72E4F2D1505E058A4613C1E977825C";
    let verdict = await vaas.forSha256(sha256);
    expect(verdict.verdict).to.equal("Clean");
    await delay(40000);
    verdict = await vaas.forSha256(sha256);
    expect(verdict.verdict).to.equal("Clean");
    expect(verdict.sha256.toUpperCase()).to.equal(sha256);
  }).timeout(45000);

  // it("returns Pup for AMTSO pup sample", async () => {
  //   const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
  //   const sha256 =
  //     "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad";
  //   let verdict = await vaas.forSha256(sha256);
  //   expect(verdict.verdict).to.equal("Pup");
  //   expect(verdict.sha256).to.equal(sha256);
  // });

  it('if a clean url is submitted, a verdict "clean" is expected', async () => {
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const verdict = await vaas.forUrl(
      new URL("https://www.gdatasoftware.com/oem/verdict-as-a-service"),
    );
    expect(verdict.verdict).to.equal("Clean");
  });

  it('if EICAR url is submitted, a verdict "malicious" is expected', async () => {
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const verdict = await vaas.forUrl(
      new URL("https://secure.eicar.org/eicar.com"),
    );
    expect(verdict.verdict).to.equal("Malicious");
  });

  it('if a clean stream is submitted, a verdict "clean" is expected', async () => {
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const stream = new Readable();
    stream.push("I am Clean");
    stream.push(null);
    const verdict = await vaas.forStream(stream);
    expect(verdict.verdict).to.equal("Clean");
  });

  it('if a EICAR stream is submitted, a verdict "malicious" is expected', async () => {
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const stream = new Readable();
    stream._read = () => {};
    stream.push(
      `X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`,
    );
    stream.push(null);
    const verdict = await vaas.forStream(stream);
    expect(verdict.verdict).to.equal("Malicious");
  });

  it('if a EICAR stream from an url is submitted, a verdict "malicious" is expected', async () => {
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const response = await axios.get<Readable>(
      "https://secure.eicar.org/eicar.com.txt",
      { responseType: "stream" },
    );
    const verdict = await vaas.forStream(response.data);
    expect(verdict.verdict).to.equal("Malicious");
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
      onopen: () => {},
      onclose: () => {},
      onmessage: () => {},
      send: (data: any) => {},
    } as any;
    vaas = new Vaas((url) => webSocket);
  });

  methodsAndParams.forEach(([method, params]) => {
    describe(`#${method}()`, () => {
      it("throws if connect() has not been called", async () => {
        const vaas = new Vaas();
        await expect((vaas as any)[method](...params)).to.be.rejectedWith(
          VaasInvalidStateError,
          "connect() was not called",
        );
      });

      it("throws if connect() was not awaited", async () => {
        vaas.connect("token", VAAS_URL);
        (webSocket as any).readyState = WebSocket.CONNECTING;

        await expect((vaas as any)[method](...params)).to.be.rejectedWith(
          VaasInvalidStateError,
          "connect() was not awaited",
        );
      });

      it("throws not authenticated if connect() was not awaited", async () => {
        vaas.connect("token", VAAS_URL);
        (webSocket as any).readyState = WebSocket.OPEN;

        await expect((vaas as any)[method](...params)).to.be.rejectedWith(
          VaasInvalidStateError,
          "Not yet authenticated - connect() was not awaited",
        );
      });

      it("throws if connection was closed", async () => {
        const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
        vaas.close();
        await expect((vaas as any)[method](...params)).to.be.rejectedWith(
          VaasConnectionClosedError,
          "Connection was closed",
        );
      });

      // it("is rejected if connection is closed by server", async () => {
      //     const authResponse = new AuthenticationResponse(
      //         "sessionId",
      //         true,
      //         "Authenticated."
      //     );
      //     await vaas.connect("token", VAAS_URL);
      //     (webSocket as any).readyState = WebSocket.OPEN;
      //     webSocket.onopen!({} as any);
      //     webSocket.onmessage!({data: JSON.stringify(authResponse)} as any);
      //     const promise = (vaas as any)[method](...params);
      //     webSocket.onclose!({wasClean: true} as any);

      //     await expect(promise).to.be.rejectedWith(
      //         VaasConnectionClosedError,
      //         "Connection was closed"
      //     );
      // });

      it("throws if authentication failed", async () => {
        const vaas = new Vaas();
        await expect(
          (async () => await vaas.connect("token", VAAS_URL))(),
        ).to.be.rejectedWith(
          VaasAuthenticationError,
          "Vaas authentication failed",
        );
        await expect((vaas as any)[method](...params)).to.be.rejectedWith(
          VaasAuthenticationError,
          "Vaas authentication failed",
        );
      });
    });
  });
});
