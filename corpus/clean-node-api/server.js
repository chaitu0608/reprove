// Vibe Shop API — the FIXED twin of corpus/vuln-node-api.
// Same features, senior-engineered: ownership checks, auth+role on admin,
// parameterized search, restricted CORS, security headers, rate limiting.
// This is the control app: reprove must find *nothing* critical here.

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 4312;

const users = [];
const orders = [];
let seq = 1;

// ---- helpers ------------------------------------------------------------------

function send(res, code, obj) {
  res.writeHead(code, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": process.env.ALLOWED_ORIGIN || "http://localhost:3000",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  });
  res.end(JSON.stringify(obj));
}

function deny(res, code) {
  return send(res, code, { error: code === 401 ? "unauthorized" : "not found" });
}

// naive in-memory rate limiting (5 requests / 10s per IP on sensitive routes)
const rateLimits = new Map();
function limited(ip, key, max = 5, windowMs = 10000) {
  const now = Date.now();
  const bucket = rateLimits.get(`${ip}:${key}`) || [];
  const recent = bucket.filter((t) => now - t < windowMs);
  recent.push(now);
  rateLimits.set(`${ip}:${key}`, recent);
  return recent.length > max;
}

function body(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try { resolve(JSON.parse(data || "{}")); } catch (e) { resolve({}); }
    });
  });
}

function hash(pw) {
  return crypto.scryptSync(String(pw), "static-salt-for-corpus", 32).toString("hex");
}

function auth(req) {
  const header = req.headers["authorization"] || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  return users.find((u) => u.token === token) || null;
}

const db = {
  query: (sql, params) => {
    const needle = String((params && params[0]) || "").replaceAll("%", "").toLowerCase();
    return orders.filter((o) => o.item.toLowerCase().includes(needle));
  },
};

// ---- server -------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  const raw = req.url;
  const qs = raw.indexOf("?");
  const pathName = qs >= 0 ? raw.slice(0, qs) : raw;
  const ip = req.socket.remoteAddress || "unknown";

  if (pathName === "/healthz") {
    return send(res, 200, { ok: true });
  }

  if (pathName === "/api/auth/signup" && req.method === "POST") {
    if (limited(ip, "signup")) {
      return send(res, 429, { error: "too many requests" });
    }
    const payload = await body(req);
    if (!payload.email || !payload.password || String(payload.password).length < 8) {
      return send(res, 400, { error: "email and password (8+ chars) required" });
    }
    if (users.find((u) => u.email === payload.email)) {
      return send(res, 409, { error: "already registered" });
    }
    const user = {
      id: "u" + seq++,
      email: payload.email,
      passwordHash: hash(payload.password),
      role: "member",
      token: crypto.randomBytes(16).toString("hex"),
    };
    users.push(user);
    return send(res, 201, { token: user.token, user: { id: user.id, email: user.email } });
  }

  if (pathName === "/api/auth/login" && req.method === "POST") {
    if (limited(ip, "login")) {
      return send(res, 429, { error: "too many requests" });
    }
    const payload = await body(req);
    const user = users.find((u) => u.email === payload.email && u.passwordHash === hash(payload.password));
    if (!user) {
      return deny(res, 401);
    }
    user.token = crypto.randomBytes(16).toString("hex");
    return send(res, 200, { token: user.token, user: { id: user.id, email: user.email } });
  }

  // Admin endpoint — authenticated AND role-checked
  if (req.url.startsWith("/api/admin/users") && req.method === "GET") {
    const user = auth(req);
    if (!user) {
      return deny(res, 401);
    }
    if (user.role !== "admin") {
      return send(res, 403, { error: "forbidden" });
    }
    const rows = users.map((u) => ({ id: u.id, email: u.email, role: u.role }));
    return send(res, 200, { users: rows, total: rows.length });
  }

  if (pathName === "/api/orders" && req.method === "POST") {
    const user = auth(req);
    if (!user) {
      return deny(res, 401);
    }
    const payload = await body(req);
    const order = {
      id: "o" + seq++,
      userId: user.id,
      item: String(payload.item || payload.name || payload.title || "item").slice(0, 200),
      createdAt: new Date().toISOString(),
    };
    orders.push(order);
    return send(res, 201, order);
  }

  if (pathName === "/api/orders" && req.method === "GET") {
    const user = auth(req);
    if (!user) {
      return deny(res, 401);
    }
    return send(res, 200, { orders: orders.filter((o) => o.userId === user.id) });
  }

  // Order detail — requires login AND ownership (the fix)
  if (req.url.startsWith("/api/orders/") && req.method === "GET") {
    const user = auth(req);
    if (!user) {
      return deny(res, 401);
    }
    const id = raw.slice("/api/orders/".length).split("?")[0];
    const order = orders.find((o) => o.id === id && o.userId === user.id);
    if (!order) {
      return deny(res, 404);
    }
    return send(res, 200, order);
  }

  if (pathName === "/search" && req.method === "GET") {
    const qIndex = raw.indexOf("q=");
    const q = qIndex >= 0 ? decodeURIComponent(raw.slice(qIndex + 2).split("&")[0]).slice(0, 100) : "";
    const sql = "SELECT * FROM orders WHERE item LIKE ?";
    const params = ["%" + q + "%"];
    const results = db.query(sql, params);
    return send(res, 200, { sql, results });
  }

  if (pathName === "/config.js") {
    const file = path.join(__dirname, "public", "config.js");
    res.writeHead(200, { "Content-Type": "application/javascript" });
    return res.end(fs.readFileSync(file, "utf8"));
  }

  if (pathName === "/") {
    res.writeHead(200, { "Content-Type": "text/html" });
    return res.end("<html><head><script src=\"/config.js\"></script></head><body><h1>Vibe Shop</h1></body></html>");
  }

  return deny(res, 404);
});

server.listen(PORT, () => {
  console.log(`vibe-shop-api (secure) listening on :${PORT}`);
});
