import http from "http";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { handler } from "./server.js";
import { handleX402Gate } from "./lib/x402/gate.js";
import { getX402DiscoveryCatalog } from "./lib/x402/challenge.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = process.env.HOSTNAME || "0.0.0.0";

const gatedHandler = (req: Request) => handleX402Gate(req, handler);

// Adapt Node http.IncomingMessage / http.ServerResponse to Web Standard Request/Response
async function nodeFetchAdapter(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  handlerFn: (request: Request) => Promise<Response>
) {
  const protocol = (req.headers["x-forwarded-proto"] as string) || "http";
  const host = req.headers["host"] || `localhost:${PORT}`;
  const fullUrl = `${protocol}://${host}${req.url}`;

  const headers = new Headers();
  for (const [key, val] of Object.entries(req.headers)) {
    if (val === undefined) continue;
    if (Array.isArray(val)) {
      for (const item of val) headers.append(key, item);
    } else {
      headers.set(key, val);
    }
  }

  let body: Buffer | null = null;
  if (req.method !== "GET" && req.method !== "HEAD") {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    }
    body = Buffer.concat(chunks);
  }

  const webReq = new Request(fullUrl, {
    method: req.method,
    headers,
    body,
    // @ts-ignore
    duplex: body ? "half" : undefined,
  });

  const webRes = await handlerFn(webReq);

  res.statusCode = webRes.status;
  webRes.headers.forEach((val, key) => {
    res.setHeader(key, val);
  });

  if (webRes.body) {
    const reader = webRes.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) res.write(value);
    }
  }
  res.end();
}

const httpServer = http.createServer(async (req, res) => {
  const urlPath = (req.url || "/").split("?")[0];

  // Set CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, payment-signature, PAYMENT-SIGNATURE, x-payment-signature, Accept"
  );
  res.setHeader(
    "Access-Control-Expose-Headers",
    "payment-required, x-payment-required, PAYMENT-RESPONSE, payment-response"
  );
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD");

  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    res.end();
    return;
  }

  if (urlPath === "/health" || urlPath === "/") {
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/json");
    res.end(
      JSON.stringify({
        ok: true,
        service: "evidiq-circuit-mcp",
        version: "1.0.0",
        timestamp: new Date().toISOString(),
      })
    );
    return;
  }

  if (urlPath === "/x402") {
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(getX402DiscoveryCatalog(), null, 2));
    return;
  }

  if (urlPath === "/skill.md") {
    const skillPath = path.join(__dirname, "../skill.md");
    if (fs.existsSync(skillPath)) {
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.end(fs.readFileSync(skillPath, "utf-8"));
    } else {
      res.statusCode = 404;
      res.end("skill.md not found");
    }
    return;
  }

  if (urlPath === "/mcp" || urlPath === "/mcp/") {
    try {
      await nodeFetchAdapter(req, res, gatedHandler);
    } catch (err: any) {
      if (!res.headersSent) {
        res.statusCode = 500;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({ error: err.message || "Internal server error" }));
      }
    }
    return;
  }

  res.statusCode = 404;
  res.end("Not Found");
});

httpServer.listen(PORT, HOST, () => {
  console.log(`EVIDIQ Circuit MCP server listening at http://${HOST}:${PORT}`);
  console.log(`Endpoints: /health, /x402, /skill.md, /mcp`);
});

// A single malformed request must never take the endpoint down. An empty POST body
// threw `Unexpected end of JSON input` from inside the MCP transport, killed the
// process, and left Traefik answering 502 — which OKX reads as an agent that does not
// respond. Log loudly and keep serving: the request is already lost, the service
// should not be.
process.on("unhandledRejection", (reason) => {
  console.error("[evidiq-circuit-mcp] unhandled rejection — staying up:", reason);
});
process.on("uncaughtException", (error) => {
  console.error("[evidiq-circuit-mcp] uncaught exception — staying up:", error);
});
