import { Client } from "discord.js";
import axios from "axios";
import * as dotenv from "dotenv";
import Vaas from "../../../src/vaas";

const client = new Client({ intents: ["GUILDS", "GUILD_MESSAGES", "DIRECT_MESSAGES"] });
dotenv.config()

client.on("ready", () => {
    console.log(`Logged in as ${client.user!.username}`);
})

client.on("messageCreate", (msg) => {
    const attachments = Array.from(msg.attachments.values());

    attachments.forEach((attachment) => {
        axios({
            url: attachment.url,
            method: 'GET',
            responseType: "arraybuffer" // important
        }).then(async (response) => {
            const vaas = new Vaas();
            const connection = await vaas.connect(process.env.VAAS_TOKEN!);
            const verdict = await vaas.forFile(connection, response.data);
            if (verdict === "Malicious") {
                msg.delete()
                    .catch(console.error);
                msg.channel.send(`${attachment.name} was deleted, because I detected it as malicious.`)
            }
        });
    })
})

client.login(process.env.DISCORD_TOKEN);
