// Vibe Shop API — a deliberately vulnerable app for the reprove corpus.
// Every flaw here is a pattern real AI builders ship. Do not deploy.
//
// Flaws (by design):
//   * GET /api/orders/:id — fetches by id, no ownership check  → IDOR
//   * GET /api/admin/users — no auth at all                    → open admin endpoint
//   * GET /search — SQL built by string concatenation          → injection pattern
//   * CORS wildcard header on every response                   → sloppy config
//   * no security headers / rate limiting                      → hygiene gaps

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 4311;

const users = [];   // {id, email, passwordHash, role, token}
const orders = [];  // {id, userId, item, createdAt}
let seq = 1;

// ---- helpers ------------------------------------------------------------------

function send(res, code, obj) {
  res.writeHead(code, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
  });
  res.end(JSON.stringify(obj));
}

function deny(res, code) {
  return send(res, code, { error: code === 401 ? "unauthorized" : "not found" });
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
  return crypto.createHash("sha256").update(String(pw)).digest("hex");
}

function auth(req) {
  const header = req.headers["authorization"] || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  return users.find((u) => u.token === token) || null;
}

// Mock data layer (stands in for a real database in the corpus)
const db = {
  query: (sql, params) => {
    if (params) {
      const needle = String(params[0] || "").replaceAll("%", "").toLowerCase();
      return orders.filter((o) => o.item.toLowerCase().includes(needle));
    }
    return orders;
  },
};

// ---- server -------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  const raw = req.url;
  const qs = raw.indexOf("?");
  const pathName = qs >= 0 ? raw.slice(0, qs) : raw;

  if (pathName === "/healthz") {
    return send(res, 200, { ok: true });
  }

  if (pathName === "/api/auth/signup" && req.method === "POST") {
    const payload = await body(req);
    if (!payload.email || !payload.password) {
      return send(res, 400, { error: "email and password required" });
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
    const payload = await body(req);
    const user = users.find((u) => u.email === payload.email && u.passwordHash === hash(payload.password));
    if (!user) {
      return deny(res, 401);
    }
    user.token = crypto.randomBytes(16).toString("hex");
    return send(res, 200, { token: user.token, user: { id: user.id, email: user.email } });
  }

  // Admin endpoint — forgot the auth check entirely (the bug)
  if (req.url.startsWith("/api/admin/users") && req.method === "GET") {
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
      item: String(payload.item || payload.name || payload.title || "item"),
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

  // Order detail — requires a login, but never checks WHO is asking (the bug)
  if (req.url.startsWith("/api/orders/") && req.method === "GET") {
    const user = auth(req);
    if (!user) {
      return deny(res, 401);
    }
    const id = raw.slice("/api/orders/".length).split("?")[0];
    const order = orders.find((o) => o.id === id);
    if (!order) {
      return deny(res, 404);
    }
    return send(res, 200, order);
  }

  if (pathName === "/search" && req.method === "GET") {
    const qIndex = raw.indexOf("q=");
    const q = qIndex >= 0 ? decodeURIComponent(raw.slice(qIndex + 2).split("&")[0]) : "";
    const sql = "SELECT * FROM orders WHERE item LIKE '%" + q + "%'";
    const results = db.query(sql);
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
  console.log(`vibe-shop-api listening on :${PORT}`);
});
