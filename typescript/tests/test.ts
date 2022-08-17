import { expect } from "chai";
import { describe } from "mocha";
import * as dotenv from "dotenv";
import Vaas from "../src/vaas";
import * as randomBytes from "random-bytes";
import { CancellationToken } from "../src/CancellationToken";
import createVaasWithClientCredentialsGrant from "../src/createVaasWithClientCredentialsGrant";

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

function createVaas() {
  return createVaasWithClientCredentialsGrant(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL,
    VAAS_URL
  );
}

const defaultTimeout: number = 10_000;

function test(foobar: string = "nix") {
  return foobar;
}

describe("Test authentication", function () {
  this.timeout(defaultTimeout);

  it("if wrong authentication token is send, an error is expected", async () => {
    const token = "ThisIsAnInvalidToken";
    const vaas = new Vaas();
    await expect((() => vaas.connect(token))()).to.be.rejectedWith(
      "Unauthorized"
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
    expect(verdict).to.equal("Clean");
  });

  it('if eicar SHA256 is submitted, a verdict "malicious" is expected', async () => {
    const vaas = await createVaas();
    const verdict = await vaas.forSha256WithCustomGuid(
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "e5f27bfe-852a-41e6-b510-926ced1f59b9"
    );
    expect(verdict).to.equal("Malicious");
  });

  it("test if eicar file is detected as malicious based on the SHA256", async () => {
    const eicarString =
      "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const eicarByteArray = new TextEncoder().encode(eicarString);
    const vaas = await createVaas();
    const verdict = await vaas.forFile(eicarByteArray);
    expect(verdict).to.equal("Malicious");
  });

  it("test if unknown file is uploaded and detected as clean", async () => {
    const randomFileContent = await randomBytes.sync(50);
    const vaas = await createVaas();
    const verdict = await vaas.forFile(randomFileContent);
    expect(verdict).to.equal("Clean");
  });

  it("if a list of SHA256 is uploaded, they are detected", async () => {
    const vaas = await createVaas();
    const verdicts = await vaas.forSha256List([
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23",
    ]);
    expect(verdicts[0]).to.equal("Malicious");
    expect(verdicts[1]).to.equal("Clean");
  });

  it("if a list unknown files is uploaded, they are detected as clean", async () => {
    const randomFileContent1 = await randomBytes.sync(50);
    const randomFileContent2 = await randomBytes.sync(50);
    const vaas = await createVaas();
    const verdict = await vaas.forFileList([
      randomFileContent1,
      randomFileContent2,
    ]);
    expect(verdict[0]).to.equal("Clean");
  });

  it("if we request the same guid twice, both calls return a result", async () => {
    const vaas = await createVaas();
    const guid =
      "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23";
    const request1 = vaas.forSha256(guid);
    const request2 = vaas.forSha256(guid);
    const verdict1 = await request1;
    const verdict2 = await request2;
    expect(verdict1).to.equal("Clean");
    expect(verdict2).to.equal("Clean");
  });

  xit("keeps connection alive", async () => {
    const vaas = await createVaas();
    const guid =
      "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23";
    let verdict = await vaas.forSha256(guid);
    expect(verdict).to.equal("Clean");
    await delay(40000);
    verdict = await vaas.forSha256(guid);
    expect(verdict).to.equal("Clean");
  }).timeout(45000);

  it("returns Pup for AMTSO pup sample", async () => {
    const vaas = await createVaas();
    const guid =
      "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad";
    let verdict = await vaas.forSha256(guid);
    expect(verdict).to.equal("Pup");
  });
});
