import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
app.use(express.raw({ type: "*/*" })); // crudo, sin JSON parse

const PUBLIC_KEY = process.env.DISCORD_PUBLIC_KEY; // tu Public Key del portal
const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL; // webhook de producción n8n
const PORT = process.env.PORT || 3000;

// Función auxiliar para transformar la public key (hex → SPKI)
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

  // PING inicial
  if (body.type === 1) {
    return res.json({ type: 1 });
  }

  // (3) Slash command u otros => ACK inmediato (deferred)
  if (interaction.type === 2) {
    console.log("sending ACK");
    // Responder a Discord YA (evita timeout)
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

// Apagar limpio (cuando EasyPanel manda SIGTERM al redeploy)
process.on("SIGTERM", () => {
  console.log("SIGTERM received");
  server.close(() => process.exit(0));
});
process.on("SIGINT", () => {
  console.log("SIGINT received");
  server.close(() => process.exit(0));
});
