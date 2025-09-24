import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import { Client, GatewayIntentBits, Events, Partials } from "discord.js";

const app = express();
app.use(express.raw({ type: "*/*" })); // raw, no JSON parsing

// ====== REQUIRED ENV VARS ======
const PUBLIC_KEY = (process.env.DISCORD_PUBLIC_KEY || "").trim(); // Public Key (HEX 64 chars or PEM)
const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL; // n8n PRODUCTION webhook for slash commands
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN; // Bot token (for Gateway)
const CHANNEL_IDS = (process.env.CHANNEL_IDS || "") // Channel IDs to listen to, comma-separated
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
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
    // Respond to Discord NOW (prevents timeout)
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

// Signed URL
const HMAC_SECRET = process.env.HMAC_SECRET || "cambia-esto";

function signHex(fid, expUnix) {
  const data = `${fid}.${expUnix}`;
  // 64 chars hex
  return crypto.createHmac("sha256", HMAC_SECRET).update(data).digest("hex");
}

function verifySignature(fid, exp, sigHex) {
  if (!fid || !exp || !sigHex) return false;
  if (Math.floor(Date.now() / 1000) > exp) return false;

  const expectedHex = signHex(fid, exp);
  // Igualar longitudes SIEMPRE antes de timingSafeEqual
  if (sigHex.length !== expectedHex.length) return false;

  // Comparamos en tiempo constante sobre buffers de igual largo
  const a = Buffer.from(sigHex, "utf8");
  const b = Buffer.from(expectedHex, "utf8");
  return crypto.timingSafeEqual(a, b);
}

app.get("/ig-image", async (req, res) => {
  try {
    const fid = String(req.query.fid || "");
    const exp = Number(req.query.exp || 0);
    const sig = String(req.query.sig || "");

    if (!verifySignature(fid, exp, sig)) {
      return res.status(403).send("Invalid or expired signature");
    }

    // Direct public URL from Drive (binary).
    // For small images, this usually suffices:
    const driveUrl = `https://drive.google.com/uc?export=download&id=${encodeURIComponent(
      fid
    )}`;

    const driveResp = await fetch(driveUrl, {
      redirect: "follow",
      // Note: do not send cookies; IG does not use them.
    });

    if (!driveResp.ok) {
      return res.status(502).send(`Drive fetch error: ${driveResp.status}`);
    }

    // Try to propagate content-type if provided; otherwise, force something reasonable
    const ct = "image/jpeg";
    res.setHeader("Content-Type", ct);
    res.setHeader("Cache-Control", "no-store"); // IG only needs to read once
    // If you know the size:
    const cl = driveResp.headers.get("content-length");
    if (cl) res.setHeader("Content-Length", cl);

    // Binary stream
    driveResp.body.pipe(res);
  } catch (err) {
    res.status(500).send(`Proxy error: ${err.message}`);
  }
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
      if (CHANNEL_IDS.length && !CHANNEL_IDS.includes(message.channelId))
        return;

      const payload = {
        event: "message_create",
        message,
        // guild_id: message.guildId || null,
        // channel_id: message.channelId,
        // message_id: message.id,
        // author: {
        //   id: message.author.id,
        //   username: message.author.username,
        //   discriminator: message.author.discriminator,
        //   tag: message.author.tag,
        // },
        // content: message.content ?? "",
        // attachments: Array.from(message.attachments.values()).map(a => ({
        //   id: a.id, url: a.url, content_type: a.contentType || null, size: a.size, filename: a.name
        // })),
        attachmentsRaw: Array.from(message.attachments.values()),
        timestamp: message.createdAt?.toISOString() || new Date().toISOString(),
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

        console.log("msg:", payload);
      }
    } catch (e) {
      console.error("message handler error:", e);
    }
  });

  client.login(BOT_TOKEN).catch((err) => {
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
