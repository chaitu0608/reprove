// Happy-path smoke test — this is what the verifier re-runs after patching.
const { test } = require("node:test");
const assert = require("node:assert");
const { spawn } = require("node:child_process");
const path = require("node:path");

const PORT = 47000 + Math.floor(Math.random() * 1000);
const BASE = `http://127.0.0.1:${PORT}`;

function start() {
  return new Promise((resolve, reject) => {
    const proc = spawn("node", [path.join(__dirname, "..", "server.js")], {
      env: { ...process.env, PORT: String(PORT) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    proc.on("error", reject);
    const deadline = Date.now() + 10000;
    const poll = setInterval(async () => {
      try {
        const r = await fetch(`${BASE}/healthz`);
        if (r.ok) { clearInterval(poll); resolve(proc); return; }
      } catch (e) { /* not up yet */ }
      if (Date.now() > deadline) { clearInterval(poll); proc.kill(); reject(new Error("server did not start")); }
    }, 150);
  });
}

test("signup -> create order -> list own orders", async () => {
  const proc = await start();
  try {
    const email = `t${Date.now()}@example.org`;
    const signup = await fetch(`${BASE}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password: "Test1234!" }),
    });
    assert.equal(signup.status, 201);
    const { token } = await signup.json();
    assert.ok(token);

    const created = await fetch(`${BASE}/api/orders`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ item: "smoke-test-item" }),
    });
    assert.equal(created.status, 201);
    const order = await created.json();
    assert.ok(order.id);

    const listed = await fetch(`${BASE}/api/orders`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(listed.status, 200);
    const data = await listed.json();
    assert.ok(data.orders.some((o) => o.id === order.id));
  } finally {
    proc.kill();
  }
});
