import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import { Client, GatewayIntentBits, Events, Partials } from "discord.js";

const app = express();
app.use(express.raw({ type: "*/*" })); // raw, no JSON parsing


// ====== REQUIRED ENV VARS ======
const PUBLIC_KEY = (process.env.DISCORD_PUBLIC_KEY || "").trim();        // Public Key (HEX 64 chars or PEM)
const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL;                      // n8n PRODUCTION webhook for slash commands
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;                          // Bot token (for Gateway)
const CHANNEL_IDS = (process.env.CHANNEL_IDS || "")                       // IDs of channels to listen to, comma-separated
  .split(",").map(s => s.trim()).filter(Boolean);
const PORT = process.env.PORT || 3000;

// Helper function to transform the public key (hex → SPKI)
function getPublicKey(pubKeyHex) {
  const spkiDer = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    Buffer.from(pubKeyHex, "hex"),
  ]);
  return crypto.createPublicKey({ key: spkiDer, format: "der", type: "spki" });
}

app.post("/interactions", async (req, res) => {
  const now = Date.now();
  const sig = req.get("x-signature-ed25519");
  const ts = req.get("x-signature-timestamp");
  const raw = req.body; // Buffer

  console.log("Received interaction:", JSON.parse(raw.toString()), sig, ts);

  if (!sig || !ts) return res.status(400).send("missing signature headers");

  const publicKey = getPublicKey(PUBLIC_KEY);
  const isValid = crypto.verify(
    null,
    Buffer.concat([Buffer.from(ts), raw]),
    publicKey,
    Buffer.from(sig, "hex")
  );

  console.log("Signature valid:", isValid);
  if (!isValid) return res.status(401).send("invalid request signature");

  const body = JSON.parse(raw.toString());

  // Initial PING
  if (body.type === 1) {
    return res.json({ type: 1 });
  }

  // (3) Slash command or others => immediate ACK (deferred)
  if (body.type === 2) {
    console.log("sending ACK");
    // Respond to Discord NOW (avoids timeout)
    res.setHeader("content-type", "application/json");
    res.status(200).send(JSON.stringify({ type: 5 }));

    try {
      fetch(N8N_WEBHOOK_URL, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: raw,
      });

      console.log("ACK sent");

      return;
    } catch (err) {
      res.status(500).send("forward failed");
    }
  }

  res.status(200).json({ type: 5 });
});

app.get("/healthz", (_, res) => res.send("ok"));
const server = app.listen(PORT, () => console.log(`proxy on :${PORT}`));


// ====== Discord.js: listen to channel messages ======
if (BOT_TOKEN) {
  const client = new Client({
    intents: [
      GatewayIntentBits.Guilds,
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent, // you need to enable "Message Content Intent" in the portal
    ],
    partials: [Partials.Channel],
  });

  client.once(Events.ClientReady, (c) => {
    console.log(`bot logged in as ${c.user.tag}`);
    if (CHANNEL_IDS.length) {
      console.log(`listening channels: ${CHANNEL_IDS.join(", ")}`);
    } else {
      console.log(`listening ALL channels (no CHANNEL_IDS set)`);
    }
  });

  client.on(Events.MessageCreate, async (message) => {
    try {
      // if (message.author?.bot) return; // ignore bots
      if (CHANNEL_IDS.length && !CHANNEL_IDS.includes(message.channelId)) return;

      const payload = {
        event: "message_create",
        message: JSON.stringify(message)
      };

      // Simple example: if you want to react locally:
      // if (payload.content.startsWith("!ping")) {
      //   await message.reply("pong!");
      // }

      // Forward to n8n (optional)
      if (N8N_WEBHOOK_URL) {
        await fetch(N8N_WEBHOOK_URL, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
        });
      } else {
        console.log("msg:", payload);
      }
    } catch (e) {
      console.error("message handler error:", e);
    }
  });

  client.login(BOT_TOKEN).catch(err => {
    console.error("discord login failed:", err);
  });
} else {
  console.log("BOT_TOKEN not defined; only running the interactions proxy.");
}


// Clean shutdown (when EasyPanel sends SIGTERM on redeploy)
process.on("SIGTERM", () => {
  console.log("SIGTERM received");
  server.close(() => process.exit(0));
});
process.on("SIGINT", () => {
  console.log("SIGINT received");
  server.close(() => process.exit(0));
});
