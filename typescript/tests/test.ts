import * as dotenv from "dotenv";
import axios, { AxiosInstance } from "axios";
import AxiosMockAdapter from "axios-mock-adapter";
import { describe, expect, test, beforeAll } from "@jest/globals";
import { Readable } from "stream";
import * as sha256 from "fast-sha256";
import * as randomBytes from "random-bytes";
import { Vaas, VAAS_URL, Authenticator } from "../src/Vaas";
import { CancellationToken } from "../src/CancellationToken";
import {
  VaasAuthenticationError,
  VaasClientError,
  VaasServerError,
  VaasTimeoutError,
} from "../src/VaasErrors";
import { ForSha256Options } from "../src/options/ForSha256Options";
import { ForFileOptions } from "../src/options/ForFileOptions";
import { ForStreamOptions } from "../src/options/ForStreamOptions";
import { ForUrlOptions } from "../src/options/ForUrlOptions";
import { VaasOptions } from "../src/options/VaasOptions";
import ClientCredentialsGrantAuthenticator from "../src/ClientCredentialsGrantAuthenticator";
import ResourceOwnerPasswordGrantAuthenticator from "../src/ResourceOwnerPasswordGrantAuthenticator";

function throwError(errorMessage: string): never {
  throw new Error(errorMessage);
}

function getFromEnvironment(key: string) {
  return (
    process.env[key] ?? throwError(`Set ${key} in environment or .env file`)
  );
}

dotenv.config();

const CLIENT_ID = getFromEnvironment("CLIENT_ID");
const CLIENT_SECRET = getFromEnvironment("CLIENT_SECRET");
const VAAS_URL_ENV = getFromEnvironment("VAAS_URL");
const TOKEN_URL = getFromEnvironment("TOKEN_URL");
const VAAS_USER_NAME = getFromEnvironment("VAAS_USER_NAME");
const VAAS_PASSWORD = getFromEnvironment("VAAS_PASSWORD");
const VAAS_CLIENT_ID = getFromEnvironment("VAAS_CLIENT_ID");

const defaultTimeout: number = 50_000;

const eicarSha256 =
  "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const eicarString =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

class AuthenticatorMock implements Authenticator {
  public token: string;

  constructor(token: string = "mock-token") {
    this.token = token;
  }

  async getToken(): Promise<string> {
    return this.token;
  }
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function fileReportUrl(sha256: string): RegExp {
  return new RegExp(
    `${escapeRegex(VAAS_URL_ENV)}/files/${sha256}/report(\\?.*)?$`,
  );
}

function fileUploadUrl(): RegExp {
  return new RegExp(`${escapeRegex(VAAS_URL_ENV)}/files(\\?.*)?$`);
}

function urlAnalysisUrl(): RegExp {
  return new RegExp(`${escapeRegex(VAAS_URL_ENV)}/urls$`);
}

function urlReportUrl(id: string): RegExp {
  return new RegExp(`${escapeRegex(VAAS_URL_ENV)}/urls/${id}/report(\\?.*)?$`);
}

function createVaas(
  baseURL: string = VAAS_URL_ENV,
  token: string = "mock-token",
  options?: VaasOptions,
): { vaas: Vaas; mock: AxiosMockAdapter; axiosInstance: AxiosInstance } {
  const axiosInstance = axios.create({
    baseURL,
    validateStatus: () => true,
  });
  const mock = new AxiosMockAdapter(axiosInstance);
  const vaas = new Vaas(new AuthenticatorMock(token), options, axiosInstance);
  return { vaas, mock, axiosInstance };
}

async function createVaasWithClientCredentialsGrantAuthenticator(): Promise<Vaas> {
  const authenticator = new ClientCredentialsGrantAuthenticator(
    CLIENT_ID,
    CLIENT_SECRET,
    TOKEN_URL,
  );
  return new Vaas(
    authenticator,
    undefined,
    axios.create({ baseURL: VAAS_URL_ENV }),
  );
}

async function createVaasWithResourceOwnerPasswordGrantAuthenticator(): Promise<Vaas> {
  const authenticator = new ResourceOwnerPasswordGrantAuthenticator(
    VAAS_CLIENT_ID,
    VAAS_USER_NAME,
    VAAS_PASSWORD,
    TOKEN_URL,
  );
  return new Vaas(
    authenticator,
    undefined,
    axios.create({ baseURL: VAAS_URL_ENV }),
  );
}

describe("Test authentication with ResourceOwnerPasswordGrantAuthenticator", function () {
  beforeAll(() => {
    jest.setTimeout(defaultTimeout);
  });

  test("if wrong authentication token is send, an error is expected", async () => {
    const { vaas, mock } = createVaas(VAAS_URL_ENV, "ThisIsAnInvalidToken");
    mock
      .onGet(
        new RegExp(`${escapeRegex(VAAS_URL_ENV)}/files/.*/report(\\?.*)?$`),
      )
      .reply(401, {
        type: "VaasAuthenticationException",
        detail: "Authentication error",
      });

    await expect(vaas.forSha256(eicarSha256)).rejects.toThrow(
      VaasAuthenticationError,
    );
  });
});

describe("Test verdict requests", function () {
  beforeAll(() => {
    jest.setTimeout(defaultTimeout);
  });

  test('if a clean SHA256 is submitted, a verdict "clean" is expected', async () => {
    const { vaas, mock } = createVaas();
    const sha256 =
      "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
    mock.onGet(fileReportUrl(sha256)).reply(200, {
      sha256,
      verdict: "Clean",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });

    const verdict = await vaas.forSha256(sha256);
    expect(verdict.verdict).toBe("Clean");
    expect(verdict.sha256.toUpperCase()).toBe(sha256.toUpperCase());
  });

  test('if eicar SHA256 is submitted, a verdict "malicious" is expected', async () => {
    const { vaas, mock } = createVaas();
    mock.onGet(fileReportUrl(eicarSha256)).reply(200, {
      sha256: eicarSha256,
      verdict: "Malicious",
      detection: "EICAR-Test-File",
      fileType: "EICAR virus test files",
      mimeType: "text/plain",
    });

    const verdict = await vaas.forSha256(eicarSha256);
    expect(verdict.verdict).toBe("Malicious");
    expect(verdict.sha256).toBe(eicarSha256);
  });

  test("test if eicar file is detected as malicious based on the SHA256", async () => {
    const eicarByteArray = new TextEncoder().encode(eicarString);
    const { vaas, mock } = createVaas(
      VAAS_URL_ENV,
      "mock-token",
      new VaasOptions(),
    );
    mock.onPost(fileUploadUrl()).reply(201, { sha256: eicarSha256 });
    mock.onGet(fileReportUrl(eicarSha256)).reply(200, {
      sha256: eicarSha256,
      verdict: "Malicious",
      detection: "EICAR-Test-File",
      fileType: "EICAR virus test files",
      mimeType: "text/plain",
    });

    const verdict = await vaas.forFile(eicarByteArray);
    expect(verdict.verdict).toBe("Malicious");
    expect(verdict.sha256).toBe(eicarSha256);
  });

  test("test if unknown file is uploaded and detected as clean", async () => {
    const randomFileContent = randomBytes.sync(50);
    const fileSha256 = Vaas.toHexString(sha256.hash(randomFileContent));
    const { vaas, mock } = createVaas();
    mock.onGet(fileReportUrl(fileSha256)).reply(200, {
      sha256: fileSha256,
      verdict: "Unknown",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });
    mock.onPost(fileUploadUrl()).reply(201, { sha256: fileSha256 });
    mock.onGet(fileReportUrl(fileSha256)).reply(200, {
      sha256: fileSha256,
      verdict: "Clean",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });

    const verdict = await vaas.forFile(randomFileContent);
    expect(verdict.verdict).toBe("Clean");
    expect(verdict.sha256).toBe(fileSha256);
  });

  test("if a list of SHA256 is uploaded, they are detected", async () => {
    const { vaas, mock } = createVaas();
    const sha256List = [
      "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2",
      "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e",
    ];
    mock.onGet(fileReportUrl(sha256List[0])).reply(200, {
      sha256: sha256List[0],
      verdict: "Malicious",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });
    mock.onGet(fileReportUrl(sha256List[1])).reply(200, {
      sha256: sha256List[1],
      verdict: "Clean",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });

    const verdicts = await vaas.forSha256List(sha256List);
    expect(verdicts[0].verdict).toBe("Malicious");
    expect(verdicts[0].sha256).toBe(sha256List[0]);
    expect(verdicts[1].verdict).toBe("Clean");
    expect(verdicts[1].sha256).toBe(sha256List[1]);
  });

  test("if a list unknown files is uploaded, they are detected as clean", async () => {
    const randomFileContent1 = randomBytes.sync(50);
    const randomFileContent2 = randomBytes.sync(50);
    const file1Sha256 = Vaas.toHexString(sha256.hash(randomFileContent1));
    const file2Sha256 = Vaas.toHexString(sha256.hash(randomFileContent2));
    const { vaas, mock } = createVaas();
    mock.onGet(fileReportUrl(file1Sha256)).reply(200, {
      sha256: file1Sha256,
      verdict: "Unknown",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });
    mock.onGet(fileReportUrl(file2Sha256)).reply(200, {
      sha256: file2Sha256,
      verdict: "Unknown",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });
    mock
      .onPost(fileUploadUrl())
      .replyOnce(201, { sha256: file1Sha256 })
      .onPost(fileUploadUrl())
      .replyOnce(201, { sha256: file2Sha256 });
    mock.onGet(fileReportUrl(file1Sha256)).reply(200, {
      sha256: file1Sha256,
      verdict: "Clean",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });
    mock.onGet(fileReportUrl(file2Sha256)).reply(200, {
      sha256: file2Sha256,
      verdict: "Clean",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });

    const verdict = await vaas.forFileList([
      randomFileContent1,
      randomFileContent2,
    ]);
    expect(verdict[0].verdict).toBe("Clean");
    expect(verdict[0].sha256).toBe(file1Sha256);
    expect(verdict[1].verdict).toBe("Clean");
    expect(verdict[1].sha256).toBe(file2Sha256);
  });

  test("if an empty file is uploaded, it is detected as clean", async () => {
    const emptyFile = new Uint8Array();
    const fileSha256 = Vaas.toHexString(sha256.hash(emptyFile));
    const { vaas, mock } = createVaas();
    mock.onGet(fileReportUrl(fileSha256)).reply(200, {
      sha256: fileSha256,
      verdict: "Unknown",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });
    mock.onPost(fileUploadUrl()).reply(201, { sha256: fileSha256 });
    mock.onGet(fileReportUrl(fileSha256)).reply(200, {
      sha256: fileSha256,
      verdict: "Clean",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });

    const verdict = await vaas.forFile(emptyFile);
    expect(verdict.verdict).toBe("Clean");
    expect(verdict.sha256).toBe(fileSha256);
  });

  test("returns Pup for AMTSO pup sample", async () => {
    const { vaas, mock } = createVaas();
    const sha256 =
      "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad";
    mock.onGet(fileReportUrl(sha256)).reply(200, {
      sha256,
      verdict: "Pup",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });

    const verdict = await vaas.forSha256(sha256);
    expect(verdict.verdict).toBe("Pup");
    expect(verdict.sha256).toBe(sha256);
  });

  test('if a clean url is submitted, a verdict "clean" is expected', async () => {
    const { vaas, mock } = createVaas();
    const url = "https://www.gdatasoftware.com/oem/verdict-as-a-service";
    const reportId = "report-id-123";
    mock.onPost(urlAnalysisUrl()).reply(201, { id: reportId });
    mock.onGet(urlReportUrl(reportId)).reply(200, {
      sha256: "some-sha256",
      verdict: "Clean",
      url,
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });

    const verdict = await vaas.forUrl(new URL(url));
    expect(verdict.verdict).toBe("Clean");
  });

  test('if EICAR url is submitted, a verdict "malicious" is expected', async () => {
    const { vaas, mock } = createVaas();
    const url = "https://secure.eicar.org/eicar.com";
    const reportId = "report-id-456";
    mock.onPost(urlAnalysisUrl()).reply(201, { id: reportId });
    mock.onGet(urlReportUrl(reportId)).reply(200, {
      sha256: eicarSha256,
      verdict: "Malicious",
      url,
      detection: "EICAR-Test-File",
      fileType: "EICAR virus test files",
      mimeType: "text/plain",
    });

    const verdict = await vaas.forUrl(new URL(url));
    expect(verdict.verdict).toBe("Malicious");
  });

  test('if a clean stream is submitted, a verdict "clean" is expected', async () => {
    const { vaas, mock } = createVaas();
    const fileSha256 =
      "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069";
    mock.onPost(fileUploadUrl()).reply(201, { sha256: fileSha256 });
    mock.onGet(fileReportUrl(fileSha256)).reply(200, {
      sha256: fileSha256,
      verdict: "Clean",
      detection: undefined,
      fileType: "ASCII text, with no line terminators",
      mimeType: "text/plain",
    });

    const stream = new Readable();
    stream.push("I am Clean");
    stream.push(null);
    const verdict = await vaas.forStream(stream);
    expect(verdict.verdict).toBe("Clean");
    expect(verdict.detection).toBeUndefined();
    expect(verdict.file_type).toBe("ASCII text, with no line terminators");
    expect(verdict.mime_type).toBe("text/plain");
  });

  test('if a EICAR stream is submitted, a verdict "malicious" is expected', async () => {
    const { vaas, mock } = createVaas();
    mock.onPost(fileUploadUrl()).reply(201, { sha256: eicarSha256 });
    mock.onGet(fileReportUrl(eicarSha256)).reply(200, {
      sha256: eicarSha256,
      verdict: "Malicious",
      detection: "EICAR-Test-File",
      fileType: "EICAR virus test files",
      mimeType: "text/plain",
    });

    const stream = new Readable();
    stream._read = () => {};
    stream.push(eicarString);
    stream.push(null);
    const verdict = await vaas.forStream(stream);
    expect(verdict.verdict).toBe("Malicious");
    expect(verdict.detection).not.toEqual("");
    expect(verdict.file_type).toBe("EICAR virus test files");
    expect(verdict.mime_type).toBe("text/plain");
  });
});

describe("Test options", function () {
  beforeAll(() => {
    jest.setTimeout(defaultTimeout);
  });

  test.each([
    [false, false],
    [false, true],
    [true, false],
    [true, true],
  ])(
    "forSha256 sends useCache=%s and useHashLookup=%s",
    async (useCache, useHashLookup) => {
      const { vaas, mock } = createVaas();
      const sha256 =
        "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
      let capturedUrl: string | undefined;
      mock.onGet(fileReportUrl(sha256)).reply((config) => {
        capturedUrl = config.url;
        return [
          200,
          {
            sha256,
            verdict: "Clean",
            detection: undefined,
            fileType: undefined,
            mimeType: undefined,
          },
        ];
      });

      await vaas.forSha256(sha256, undefined, {
        useCache,
        useHashLookup,
      } as ForSha256Options);

      expect(capturedUrl).toContain(`useCache=${useCache}`);
      expect(capturedUrl).toContain(`useHashLookup=${useHashLookup}`);
    },
  );

  test("forSha256 sends User-Agent header", async () => {
    const { vaas, mock } = createVaas();
    const sha256 =
      "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
    let capturedHeaders: Record<string, string> | undefined;
    mock.onGet(fileReportUrl(sha256)).reply((config) => {
      capturedHeaders = config.headers as Record<string, string>;
      return [
        200,
        {
          sha256,
          verdict: "Clean",
          detection: undefined,
          fileType: undefined,
          mimeType: undefined,
        },
      ];
    });

    await vaas.forSha256(sha256);

    expect(capturedHeaders?.["User-Agent"]).toContain("gdata-vaas-typescript");
  });

  test("forSha256 sends tracestate when vaasRequestId is set", async () => {
    const { vaas, mock } = createVaas();
    const sha256 =
      "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
    let capturedHeaders: Record<string, string> | undefined;
    mock.onGet(fileReportUrl(sha256)).reply((config) => {
      capturedHeaders = config.headers as Record<string, string>;
      return [
        200,
        {
          sha256,
          verdict: "Clean",
          detection: undefined,
          fileType: undefined,
          mimeType: undefined,
        },
      ];
    });

    await vaas.forSha256(
      sha256,
      undefined,
      new ForSha256Options({ vaasRequestId: "foobar" }),
    );

    expect(capturedHeaders?.["tracestate"]).toBe("vaasrequestid=foobar");
  });
});

describe("Test errors", function () {
  beforeAll(() => {
    jest.setTimeout(defaultTimeout);
  });

  test("if a request times out, an error is expected", async () => {
    const { vaas, mock } = createVaas();
    const randomFileContent = randomBytes.sync(50);
    const fileSha256 = Vaas.toHexString(sha256.hash(randomFileContent));
    mock.onGet(fileReportUrl(fileSha256)).reply(200, {
      sha256: fileSha256,
      verdict: "Unknown",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });
    mock
      .onPost(fileUploadUrl())
      .reply(
        () =>
          new Promise((resolve) =>
            setTimeout(() => resolve([201, { sha256: fileSha256 }]), 1000),
          ),
      );
    mock.onGet(fileReportUrl(fileSha256)).reply(200, {
      sha256: fileSha256,
      verdict: "Clean",
      detection: undefined,
      fileType: undefined,
      mimeType: undefined,
    });

    const promise = vaas.forFile(
      randomFileContent,
      CancellationToken.fromMilliseconds(1),
    );
    await expect(promise).rejects.toThrow(VaasTimeoutError);
  });

  test("if server returns VaasClientException, VaasClientError is thrown", async () => {
    const { vaas, mock } = createVaas();
    const sha256 =
      "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
    mock.onGet(fileReportUrl(sha256)).reply(400, {
      type: "VaasClientException",
      detail: "Mocked client-side error",
    });

    await expect(vaas.forSha256(sha256)).rejects.toThrow(VaasClientError);
  });

  test("if server returns VaasServerException, VaasServerError is thrown", async () => {
    const { vaas, mock } = createVaas();
    const sha256 =
      "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
    mock.onGet(fileReportUrl(sha256)).reply(500, {
      type: "VaasServerException",
      detail: "Mocked server-side error",
    });

    await expect(vaas.forSha256(sha256)).rejects.toThrow(VaasServerError);
  });

  test("if server returns 401, VaasAuthenticationError is thrown", async () => {
    const { vaas, mock } = createVaas();
    const sha256 =
      "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e";
    mock
      .onGet(fileReportUrl(sha256))
      .reply(401, {
        type: "VaasAuthenticationException",
        detail: "Unauthorized",
      });

    await expect(vaas.forSha256(sha256)).rejects.toThrow(
      VaasAuthenticationError,
    );
  });

  test("if authenticator fails, error is propagated", async () => {
    const axiosInstance = axios.create({
      baseURL: VAAS_URL_ENV,
      validateStatus: () => true,
    });
    const vaas = new Vaas(
      {
        getToken: () => Promise.reject(new Error("Auth failed")),
      },
      undefined,
      axiosInstance,
    );

    await expect(vaas.forSha256(eicarSha256)).rejects.toThrow("Auth failed");
  });
});

describe("Test live integration", function () {
  beforeAll(() => {
    jest.setTimeout(defaultTimeout);
  });

  test('if a clean SHA256 is submitted, a verdict "clean" is expected', async () => {
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const verdict = await vaas.forSha256(
      "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e",
    );
    expect(verdict.verdict).toBe("Clean");
  });

  test('if eicar SHA256 is submitted, a verdict "malicious" is expected', async () => {
    const vaas = await createVaasWithClientCredentialsGrantAuthenticator();
    const verdict = await vaas.forSha256(eicarSha256);
    expect(verdict.verdict).toBe("Malicious");
  });
});
