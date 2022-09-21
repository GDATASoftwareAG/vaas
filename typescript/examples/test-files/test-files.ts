import { promises as fs } from "fs";
import { CreateVaasWithClientCredentialsGrant } from "gdata-vaas";

async function main() {
    const vaas = await CreateVaasWithClientCredentialsGrant(
        "clientID",
        "clientSecret",
        "https://keycloak-vaas.gdatasecurity.de/realms/vaas/protocol/openid-connect/token"
        );
    const f = await fs.open("/path/to/file", "r");
    try{
        const verdict = await vaas.forFile(await f.readFile());
        console.log(verdict);
    }
    finally{
        f.close();
        vaas.close();
    }    
}

main().catch(e => { console.log(e) })