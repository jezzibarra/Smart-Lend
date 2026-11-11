import { spawn } from "child_process";

async function waitForServer(base, timeout = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const res = await fetch(base + "/api/rates");
      if (res.ok) return true;
    } catch (e) {}
    await new Promise(r => setTimeout(r, 500));
  }
  return false;
}

async function testLogin() {
  const BASE = "http://127.0.0.1:5000";
  
  const server = spawn("node", ["server.js"], {
    cwd: "C:/xampp/htdocs/Smart.Lend.App",
    env: {
      ...process.env,
      MONGODB_URI: "mongodb://127.0.0.1:27017/smart_lend_db",
      NODE_ENV: "development",
      JWT_SECRET: "dev-secret-local-testing-only",
      INITIAL_ADMIN_USERNAME: "admin",
      INITIAL_ADMIN_EMAIL: "admin@smartlend.local",
      INITIAL_ADMIN_PASSWORD: "Admin12345!",
      LENDING_MONTHLY_RATE: "0.05",
      LENDING_PROCESSING_FEE_RATE: "0.02"
    },
    stdio: ["ignore", "pipe", "pipe"]
  });

  server.stdout.on("data", (data) => {
    const text = data.toString();
    console.log("[SERVER]", text.trim());
  });
  server.stderr.on("data", (data) => {
    console.error("[SERVER ERR]", data.toString().trim());
  });

  try {
    console.log("Waiting for server to start...");
    const ready = await waitForServer("http://127.0.0.1:5000");
    if (!ready) throw new Error("Server did not start in time");
    console.log("Server is ready");

    console.log("\n--- Testing admin login with username \"admin\" ---");
    let res1 = await fetch("http://127.0.0.1:5000/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "Admin12345!" })
    });
    console.log("Status:", res1.status);
    const body1 = await res1.json();
    console.log("Response:", JSON.stringify(body1, null, 2));
    if (res1.status !== 200) throw new Error("Admin login with username failed");

    console.log("\n--- Testing admin login with email \"admin@smartlend.local\" ---");
    let res2 = await fetch("http://127.0.0.1:5000/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin@smartlend.local", password: "Admin12345!" })
    });
    console.log("Status:", res2.status);
    const body2 = await res2.json();
    console.log("Response:", JSON.stringify(body2, null, 2));
    if (res2.status !== 200) throw new Error("Admin login with email failed");

    console.log("\n--- Testing with wrong password ---");
    let res3 = await fetch("http://127.0.0.1:5000/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "wrong" })
    });
    console.log("Status:", res3.status);
    const body3 = await res3.json();
    console.log("Response:", JSON.stringify(body3, null, 2));
    if (res3.status !== 401) throw new Error("Wrong password should return 401");

    console.log("\nAll tests passed!");
    return true;
  } catch (err) {
    console.error("Test failed:", err);
    return false;
  } finally {
    server.kill();
  }
}

await testLogin().then(success => {
  process.exit(success ? 0 : 1);
}).catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
