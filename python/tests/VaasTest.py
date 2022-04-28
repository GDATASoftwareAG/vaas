import base64
import os
import unittest
from dotenv import load_dotenv

from src.Vaas import Vaas


load_dotenv()

TOKEN = os.getenv('VAAS_TOKEN')
EICAR_BASE64 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="


class VaasTest(unittest.IsolatedAsyncioTestCase):
    async def test_raises_error_if_token_is_invalid(self):
        async with Vaas() as vaas:
            token = "ThisIsAnInvalidToken"
            with self.assertRaises(Exception):
                await vaas.connect(token)

    async def test_connects(self):
        async with Vaas() as vaas:
            await vaas.connect(TOKEN)

    async def test_for_sha256_returns_clean_for_clean_sha256(self):
        async with Vaas() as vaas:
            await vaas.connect(TOKEN)
            verdict = await vaas.for_sha256("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23")
            self.assertEqual(verdict, "Clean")

    async def test_for_sha256_returns_malicious_for_eicar(self):
        async with Vaas() as vaas:
            await vaas.connect(TOKEN)
            verdict = await vaas.for_sha256("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            self.assertEqual(verdict, "Malicious")

    async def test_for_buffer_returns_malicious_for_eicar(self):
        async with Vaas() as vaas:
            await vaas.connect(TOKEN)
            buffer = base64.b64decode(EICAR_BASE64)
            verdict = await vaas.for_buffer(buffer)
            self.assertEqual(verdict, "Malicious")

    async def test_for_buffer_returns_unknown_for_random_buffer(self):
        async with Vaas() as vaas:
            await vaas.connect(TOKEN)
            buffer = os.urandom(1024)
            verdict = await vaas.for_buffer(buffer)
            self.assertEqual(verdict, "Clean")


if __name__ == '__main__':
    unittest.main()

# describe('Test cancellation through timeout', () => {
#     it('if a request is cancelled, an error is expected', async () => {
#         dotenv.config();
#         const token = process.env.VAAS_TOKEN!;
#         const randomFileContent = await randomBytes.sync(50);
#         const vaas = new Vaas();
#         await vaas.connect(token)
#         // Cancel promise after 1ms
#         const promise = vaas.forFile(randomFileContent, CancellationToken.fromMilliseconds(1));
#         expect(promise).to.eventually.be.rejectedWith("Cancelled");
#     }).timeout(testTimeoutHashReq);
# });





#     it('test if eicar file is detected as malicious based on the SHA256', async () => {
#         dotenv.config();
#         const token = process.env.VAAS_TOKEN!;
#         const eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
#         const eicarByteArray = new TextEncoder().encode(eicarString);
#         try {
#             const vaas = new Vaas();
#             await vaas.connect(token)
#             const verdict = await vaas.forFile(eicarByteArray);
#             expect(verdict).to.equal("Malicious");
#         } catch (error) {
#             throw new Error(error as string);
#         }
#     }).timeout(testTimeoutHashReq);

#     it('test if unknown file is uploaded and detected as clean', async () => {
#         dotenv.config();
#         const token = process.env.VAAS_TOKEN!;
#         const randomFileContent = await randomBytes.sync(50);
#         try {
#             const vaas = new Vaas();
#             await vaas.connect(token)
#             const verdict = await vaas.forFile(randomFileContent);
#             expect(verdict).to.equal("Clean");
#         } catch (error) {
#             throw new Error(error as string);
#         }
#     }).timeout(testTimeoutFileReq);

#     it('test if there is a mismatch between submitted hash for file and uploaded file', async () => {
#         dotenv.config();
#         const token = process.env.VAAS_TOKEN!;
#         const randomFileContent = await randomBytes.sync(50);
#         const sample = Vaas.toHexString(sha256.hash(randomFileContent));
#         try
#         {
#             const vaas = new Vaas();
#             await vaas.connect(token)
#             const verdictResponse = await vaas.forRequest(sample, CancellationToken.fromMilliseconds(2_000));
#             const otherRandomFile = await randomBytes.sync(40)
#             await vaas.upload(verdictResponse, otherRandomFile);
#         }
#         catch (error)
#         {
#             expect(error).to.equal("Upload failed with 400 - Error Bad request: Wrong file");
#         }
#     }).timeout(testTimeoutFileReq);
#     it('if a list of SHA256 is uploaded, they are detected', async () => {
#         dotenv.config();
#         const token = process.env.VAAS_TOKEN!;
#         const vaas = new Vaas();
#         try {
#             await vaas.connect(token);
#             const verdicts = await vaas.forSha256List(["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
#                 "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23"]);
#             expect(verdicts[0]).to.equal("Malicious");
#             expect(verdicts[1]).to.equal("Clean");
#         } catch (error) {
#             throw new Error(error as string);
#         }
#     });

#     it('if a list unknown files is uploaded, they are detected as clean', async () => {
#         dotenv.config();
#         const token = process.env.VAAS_TOKEN!;
#         const randomFileContent1 = await randomBytes.sync(50);
#         const randomFileContent2 = await randomBytes.sync(50);
#         try {
#             const vaas = new Vaas();
#             await vaas.connect(token)
#             const verdict = await vaas.forFileList([randomFileContent1, randomFileContent2]);
#             expect(verdict[0]).to.equal("Clean");
#             expect(verdict[0]).to.equal("Clean");
#         } catch (error) {
#             throw new Error(error as string);
#         }
#     }).timeout(testTimeoutFileReq);
# })
