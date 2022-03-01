import {expect} from 'chai';
import {describe} from 'mocha';
import * as dotenv from "dotenv";
import {Vaas} from '../src/vaas';
import * as randomBytes from 'random-bytes';

describe('Test authentication', () => {
    it('if wrong authentication token is send, an error is expected', async () => {
        dotenv.config();
        const token = "ThisIsAnInvalidToken";
        const vaas = new Vaas();
        try {
            const _ = await vaas.connect(token);
            throw new Error("This should not be thrown.");
        } catch (error) {
            expect(error).to.equal("Unauthorized");
        }
    })
})

describe('Test verdict requests', () => {
    it('if a clean SHA256 is submitted, a verdict "clean" is expected', async () => {
        dotenv.config();
        const token = process.env.VAAS_TOKEN!;
        const vaas = new Vaas();
        try {
            const con = await vaas.connect(token);
            const verdict = await vaas.forSha256(con, "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23");
            expect(verdict).to.equal("Clean");
        } catch (error) {
            throw new Error(error as string);
        }
    });

    it('if eicar SHA256 is submitted, a verdict "malicious" is expected', async () => {
        dotenv.config();
        const token = process.env.VAAS_TOKEN!;
        const vaas = new Vaas();
        try {
            const con = await vaas.connect(token);
            const verdict = await vaas.forSha256(con, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f");
            expect(verdict).to.equal("Malicious");
        } catch (error) {
            throw new Error(error as string);
        }
    });

    it('test if eicar file is detected as malicious based on the SHA256', async () => {
        dotenv.config();
        const token = process.env.VAAS_TOKEN!;
        const eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        const eicarByteArray = new TextEncoder().encode(eicarString);
        try {
            const vaas = new Vaas();
            const con = await vaas.connect(token)
            const verdict = await vaas.forFile(con, eicarByteArray);
            expect(verdict).to.equal("Malicious");
        } catch (error) {
            throw new Error(error as string);
        }
    });

    it('test if unknown file is uploaded and detected as clean', async () => {
        dotenv.config();
        const token = process.env.VAAS_TOKEN!;
        const randomFileContent = await randomBytes.sync(50);
        try {
            const vaas = new Vaas();
            const con = await vaas.connect(token)
            const verdict = await vaas.forFile(con, randomFileContent);
            expect(verdict).to.equal("Clean");
        } catch (error) {
            throw new Error(error as string);
        }
    }).timeout(300_000);

    it('if a list of SHA256 is uploaded, they are detected', async () => {
        dotenv.config();
        const token = process.env.VAAS_TOKEN!;
        const vaas = new Vaas();
        try {
            const con = await vaas.connect(token);
            const verdicts = await vaas.forSha256List(con, ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23"]);
            expect(verdicts[0]).to.equal("Malicious");
            expect(verdicts[1]).to.equal("Clean");
        } catch (error) {
            throw new Error(error as string);
        }
    });

    it('if a list unknown files is uploaded, theay are detected as clean', async () => {
        dotenv.config();
        const token = process.env.VAAS_TOKEN!;
        const randomFileContent1 = await randomBytes.sync(50);
        const randomFileContent2 = await randomBytes.sync(50);
        try {
            const vaas = new Vaas();
            const con = await vaas.connect(token)
            const verdict = await vaas.forFileList(con, [randomFileContent1, randomFileContent2]);
            expect(verdict[0]).to.equal("Clean");
            expect(verdict[0]).to.equal("Clean");
        } catch (error) {
            throw new Error(error as string);
        }
    }).timeout(300_000);
})
