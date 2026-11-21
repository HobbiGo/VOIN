// VOIN Cloudflare Worker — Web3 ke Web4 Development Preview
// Catatan: Tetap arahkan transaksi on-chain ke jaringan uji coba (BSC Testnet / Chain ID 97)
// selama tahap pengembangan dan verifikasi keamanan belum selesai[span_2](start_span)[span_2](end_span)[span_3](start_span)[span_3](end_span).

const DEFAULT_CONTRACT = "0xf6e7a0cd45e0f98b383273888c79ae548a4abb05"; //[span_4](start_span)[span_4](end_span)[span_5](start_span)[span_5](end_span)
const DEFAULT_CHAIN_ID = 97; // BSC Testnet[span_6](start_span)[span_6](end_span)[span_7](start_span)[span_7](end_span)
const PLANNED_MAX_SUPPLY = 260_000_000; //[span_8](start_span)[span_8](end_span)[span_9](start_span)[span_9](end_span)

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extraHeaders,
    },
  });
}

function handleApi(request, env, url) {
  const path = url.pathname;

  if (path === "/api/health") {
    return jsonResponse({
      ok: true,
      service: "voin-worker",
      mode: env.VOIN_ENV_MODE || "development-preview",
      timestamp: new Date().toISOString(),
    });
  }

  if (path === "/api/info") {
    return jsonResponse({
      project: "VOIN",
      symbol: "$VOIN",
      planned_max_supply: PLANNED_MAX_SUPPLY, //[span_10](start_span)[span_10](end_span)[span_11](start_span)[span_11](end_span)
      active_wallet_network: {
        name: "BSC Testnet", //[span_12](start_span)[span_12](end_span)[span_13](start_span)[span_13](end_span)
        chain_id: Number(env.VOIN_CHAIN_ID || DEFAULT_CHAIN_ID), //[span_14](start_span)[span_14](end_span)[span_15](start_span)[span_15](end_span)
        presale_test_contract: env.VOIN_CONTRACT_ADDRESS || DEFAULT_CONTRACT, //[span_16](start_span)[span_16](end_span)[span_17](start_span)[span_17](end_span)
      },
      custom_l1_reference: {
        network_name: "VOIN Mainnet (Genesis Config)",
        chain_id: 260,
        status: "prototype-in-development", //[span_18](start_span)[span_18](end_span)[span_19](start_span)[span_19](end_span)
      },
      web4_modules_status: {
        core_and_hybrid_pqc_node: "experimental / prototype", //[span_20](start_span)[span_20](end_span)[span_21](start_span)[span_21](end_span)
        ai_engine: "planned / research", //[span_22](start_span)[span_22](end_span)
        mainnet_and_live_presale: "not_active", //[span_23](start_span)[span_23](end_span)[span_24](start_span)[span_24](end_span)
      },
      disclaimer:
        "Testnet & development preview only. Not a live token sale, financial advice, or production Web4/mainnet guarantee.", //[span_25](start_span)[span_25](end_span)[span_26](start_span)[span_26](end_span)
    });
  }

  // Contoh endpoint untuk menghubungkan status node P2P jika NODE_API_URL diset di env
  if (path === "/api/node-status") {
    if (!env.NODE_API_URL) {
      return jsonResponse(
        {
          error: "NODE_API_URL belum dikonfigurasi pada Worker environment.",
        },
        503
      );
    }
    return proxyNodeStatus(env.NODE_API_URL);
  }

  return jsonResponse(
    {
      error: "Endpoint API tidak ditemukan.",
      available_endpoints: ["/api/health", "/api/info", "/api/node-status"],
    },
    404
  );
}

async function proxyNodeStatus(nodeBaseUrl) {
  const cleanBase = nodeBaseUrl.replace(/\/+$/, "");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4000);

  try {
    const res = await fetch(`${cleanBase}/info`, {
      method: "GET",
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });
    const text = await res.text();
    return new Response(text, {
      status: res.status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  } catch (err) {
    return jsonResponse(
      {
        error: "Gagal menghubungi VOIN node.",
        detail: err?.name === "AbortError" ? "Timeout" : String(err?.message || err),
      },
      502
    );
  } finally {
    clearTimeout(timeout);
  }
}

function renderHtml(projectId, contractAddress, chainId) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>VOIN — Web3 to Web4 Development Preview</title>
  <style>
    :root {
      --bg: #050d1b;
      --card: #0c1f3a;
      --line: rgba(132, 177, 231, 0.22);
      --text: #f3f7ff;
      --muted: #9eb3cc;
      --gold: #efd18b;
      --cyan: #2de2f2;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: radial-gradient(circle at 80% 10%, #12315c 0%, var(--bg) 45%);
      color: var(--text);
      line-height: 1.6;
    }
    .wrap { max-width: 1040px; margin: 0 auto; padding: 32px 20px 64px; }
    .top {
      display: flex; justify-content: space-between; align-items: center;
      gap: 12px; flex-wrap: wrap; padding-bottom: 20px; border-bottom: 1px solid var(--line);
    }
    .brand { font-weight: 800; letter-spacing: 2px; color: var(--gold); font-size: 20px; }
    .badge {
      font-size: 12px; padding: 6px 12px; border-radius: 999px;
      border: 1px solid rgba(45, 226, 242, 0.45); color: var(--cyan); background: rgba(45, 226, 242, 0.08);
    }
    h1 { font-size: clamp(32px, 5vw, 52px); line-height: 1.1; margin: 28px 0 12px; }
    h1 span { color: var(--gold); }
    .lead { color: var(--muted); max-width: 680px; font-size: 17px; }
    .actions { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 22px; }
    button, a.btn {
      border-radius: 10px; padding: 12px 18px; font-weight: 700; font-size: 14px;
      cursor: pointer; text-decoration: none; border: 1px solid transparent;
    }
    .btn-gold { background: linear-gradient(120deg, #c28e34, #ffe5a3, #d6ac54); color: #121826; }
    .btn-ghost { background: rgba(255,255,255,0.04); color: var(--text); border-color: var(--line); }
    .grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px; margin-top: 32px;
    }
    .card {
      background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 20px;
    }
    .card h3 { margin: 0 0 8px; font-size: 17px; color: var(--gold); }
    .card p { margin: 0; color: var(--muted); font-size: 14px; }
    .status-box {
      margin-top: 24px; background: rgba(6, 16, 34, 0.85);
      border: 1px solid var(--line); border-radius: 14px; padding: 16px;
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px; color: #bfe8ff;
      white-space: pre-wrap; word-break: break-word;
    }
    .warn {
      margin-top: 20px; padding: 14px 16px; border-radius: 12px;
      border: 1px solid rgba(239, 209, 139, 0.45); background: rgba(239, 209, 139, 0.08);
      color: #f6e2b3; font-size: 13px;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header class="top">
      <div class="brand">VOIN PROTOCOL</div>
      <div class="badge">TESTNET &amp; WEB4 R&amp;D PREVIEW · CHAIN ${chainId}</div>
    </header>

    <main>
      <h1>Web3 Foundation to <span>Web4 Ecosystem</span></h1>
      <p class="lead">
        Exploration build for VOIN: combining Layer-1 / EVM testnet workflows, post-quantum signature research (ML-DSA),
        and staged AI/automation modules.
      </p>

      <div class="actions">
        <button class="btn btn-gold" id="btnConnect" type="button">Connect Wallet (Testnet)</button>
        <button class="btn btn-ghost" id="btnApiInfo" type="button">Check /api/info</button>
        <a class="btn btn-ghost" href="https://testnet.bscscan.com/address/${contractAddress}" target="_blank" rel="noopener noreferrer">View Test Contract ↗</a>
      </div>

      <div class="grid">
        <div class="card">
          <h3>01 / Layer-1 &amp; Presale Testnet</h3>
          <p>Current test contract configured on Chain ID ${chainId} with planned max supply of 260,000,000 VOIN.</p>
        </div>
        <div class="card">
          <h3>02 / Hybrid &amp; PQC Security</h3>
          <p>Research &amp; prototyping with EVM signatures and NIST FIPS 204 (ML-DSA) before any production rollout.</p>
        </div>
        <div class="card">
          <h3>03 / Web4 &amp; AI Modules</h3>
          <p>Staged development for analytics, monitoring, and agent/workflow tooling—built step by step.</p>
        </div>
      </div>

      <div class="status-box" id="output">Wallet status: Not connected.
Reown Project ID configured: ${projectId ? "Yes" : "No"}
Contract: ${contractAddress}</div>

      <div class="warn">
        <strong>Notice:</strong> Testnet &amp; development preview only. Do not send real funds or treat test allocations as live tokens or guaranteed returns.
      </div>
    </main>
  </div>

  <script type="module">
    const projectId = ${JSON.stringify(projectId)};
    const output = document.getElementById("output");
    const btnConnect = document.getElementById("btnConnect");
    const btnApiInfo = document.getElementById("btnApiInfo");

    function log(msg) {
      output.textContent = msg;
    }

    btnApiInfo.addEventListener("click", async () => {
      log("Fetching /api/info...");
      try {
        const res = await fetch("/api/info");
        const data = await res.json();
        log(JSON.stringify(data, null, 2));
      } catch (err) {
        log("Failed to fetch /api/info: " + err.message);
      }
    });

    let appKitModal = null;
    try {
      const [{ createAppKit }, { EthersAdapter }, networks] = await Promise.all([
        import("https://esm.sh/@reown/appkit@1.8.24?target=es2022"),
        import("https://esm.sh/@reown/appkit-adapter-ethers@1.8.24?target=es2022"),
        import("https://esm.sh/@reown/appkit@1.8.24/networks?target=es2022"),
      ]);

      appKitModal = createAppKit({
        adapters: [new EthersAdapter()],
        networks: [networks.bscTestnet],
        projectId,
        metadata: {
          name: "VOIN Web4 Preview",
          description: "VOIN Testnet & Web4 development preview",
          url: window.location.origin,
          icons: [],
        },
        features: { analytics: false, email: false, socials: false, swaps: false, onramp: false },
        themeMode: "dark",
      });

      appKitModal.subscribeAccount((acc) => {
        if (acc?.isConnected && acc?.address) {
          btnConnect.textContent = acc.address.slice(0, 6) + "..." + acc.address.slice(-4);
          log("Connected wallet: " + acc.address + "\\nNetwork: BSC Testnet (Chain ID 97)");
        } else {
          btnConnect.textContent = "Connect Wallet (Testnet)";
        }
      });
    } catch (err) {
      console.error("AppKit load error:", err);
      log("Wallet modal failed to load: " + err.message);
    }

    btnConnect.addEventListener("click", async () => {
      if (!appKitModal) {
        log("Wallet connector is not ready yet.");
        return;
      }
      await appKitModal.open({ view: "Connect", namespace: "eip155" });
    });
  </script>
</body>
</html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      return handleApi(request, env, url);
    }

    if (!["GET", "HEAD"].includes(request.method)) {
      return new Response("Method not allowed", { status: 405 });
    }

    const projectId = env.REOWN_PROJECT_ID;
    if (!projectId) {
      return new Response(
        "Configuration error: REOWN_PROJECT_ID is not set in Cloudflare Secrets.",
        { status: 500 }
      );
    }

    const contractAddress = env.VOIN_CONTRACT_ADDRESS || DEFAULT_CONTRACT;
    const chainId = Number(env.VOIN_CHAIN_ID || DEFAULT_CHAIN_ID);
    const html = renderHtml(projectId, contractAddress, chainId);

    return new Response(request.method === "HEAD" ? null : html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  },
};
