import { Client } from "discord.js";
import axios from "axios";
import * as dotenv from "dotenv";
import {
    ClientCredentialsGrantAuthenticator,
    Vaas,
  } from "gdata-vaas";

  function throwError(errorMessage: string): never {
    throw new Error(errorMessage);
  }
  
  function getFromEnvironment(key: string) {
    return (
      process.env[key] ?? throwError(`Set ${key} in environment or .env file`)
    );
  }
  
const client = new Client({ intents: ["Guilds", "GuildMessages", "DirectMessages", "MessageContent"]});
dotenv.config()

client.on("ready", () => {
    console.log(`Logged in as ${client.user!.username}`);
})

const DISCORD_TOKEN = getFromEnvironment("DISCORD_TOKEN")
const CLIENT_ID = getFromEnvironment("CLIENT_ID");
const CLIENT_SECRET = getFromEnvironment("CLIENT_SECRET");
const TOKEN_URL =
  "https://account.gdata.de/realms/vaas-production/protocol/openid-connect/token";


client.on("messageCreate", (msg) => {
    const attachments = Array.from(msg.attachments.values());

    attachments.forEach((attachment) => {
        axios({
            url: attachment.url,
            method: 'GET',
            responseType: "arraybuffer" // important
        }).then(async (response) => {
            console.log(`Scan File ${attachment.name}`)
            const authenticator = new ClientCredentialsGrantAuthenticator(
                CLIENT_ID,
                CLIENT_SECRET,
                TOKEN_URL
              );
            
            const vaas = new Vaas();
            const token = await authenticator.getToken()
            await vaas.connect(token);
            const verdict = await vaas.forFile(response.data);
            if (verdict.verdict === "Malicious") {
                msg.delete()
                    .catch(console.error);
                msg.channel.send(`${attachment.name} was deleted, because I detected it as malicious.`)
            }
        });
    })
})

client.login(DISCORD_TOKEN);
