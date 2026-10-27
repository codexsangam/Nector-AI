#!/usr/bin/env node
/* ============================================================
   Nector — static file server with security headers.

   This is NOT the scanning backend. It only serves the files in
   this folder (index.html, styles.css, script.js) and attaches
   hardened response headers to every response:

     Content-Security-Policy   locks the page down to its own
                               files + the local API origin
     X-Frame-Options: DENY     prevents clickjacking
     X-Content-Type-Options    stops MIME sniffing
     Referrer-Policy           never leak referrer data
     Permissions-Policy        disables camera/mic/geo/...
     COOP / CORP               process & resource isolation

   Usage:   node threatforge/serve.mjs
   Env:     PORT=8080  HOST=127.0.0.1   (HOST=0.0.0.0 to expose on LAN)
   ============================================================ */

import http from "node:http";
import { createReadStream, statSync } from "node:fs";
import { join, normalize, extname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL(".", import.meta.url));
const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 8080);

// Keep this identical to the <meta http-equiv="Content-Security-Policy">
// in index.html, so header- and meta-based CSP enforce the same policy.
const CSP =
  "default-src 'none'; " +
  "script-src 'self'; " +
  "style-src 'self'; " +
  "img-src 'self' data:; " +
  "font-src 'self'; " +
  "connect-src 'self' http://localhost:3000 http://127.0.0.1:3000 http://[::1]:3000; " +
  "base-uri 'none'; form-action 'none'; frame-src 'none'; " +
  "object-src 'none'; worker-src 'none'; manifest-src 'none'; media-src 'none'";

const PERMISSIONS_POLICY =
  "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".md": "text/markdown; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

function sendSecurityHeaders(res, isHtml) {
  res.setHeader("Content-Security-Policy", CSP);
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", PERMISSIONS_POLICY);
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
  // The assessment is per-visit; never let a proxy hand out a stale page
  res.setHeader("Cache-Control", isHtml ? "no-store" : "no-cache");
}

const server = http.createServer((req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { Allow: "GET, HEAD" });
    res.end("Method not allowed");
    return;
  }

  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
  } catch (err) {
    res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Bad request");
    return;
  }
  if (pathname.includes("\0")) {
    res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Bad request");
    return;
  }
  if (pathname === "/" || pathname === "") pathname = "/index.html";

  // Resolve inside this folder only — no traversal, no directory listing
  const filePath = normalize(join(ROOT, pathname));
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Forbidden");
    return;
  }

  let stat;
  try {
    stat = statSync(filePath);
  } catch (err) {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }
  if (!stat.isFile()) {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }

  const type = MIME[extname(filePath).toLowerCase()] || "application/octet-stream";
  sendSecurityHeaders(res, type.startsWith("text/html"));
  res.writeHead(200, { "Content-Type": type });

  if (req.method === "HEAD") {
    res.end();
    return;
  }

  const stream = createReadStream(filePath);
  stream.on("error", () => {
    res.destroy();
  });
  stream.pipe(res);
});

server.listen(PORT, HOST, () => {
  console.log(
    `Nector frontend running at http://${HOST}:${PORT}\n` +
      `Security headers: CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP\n` +
      `The page expects the scanning API on http://localhost:3000 (node server.js).`
  );
});
