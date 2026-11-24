const DEFAULT_GATEWAY_URL = "";
const DEFAULT_API_TOKEN = "";

const PRESALE_PUBLIC_CONFIG = {
  treasuryAddress: "0xAEb22359588A50e6F746004E66418Eb2c978dAA2",
  schedule: {
    startTimestampUtc: 1796083200, // 1 Desember 2026 00:00:00 UTC
    endTimestampUtc: 1861919999,   // 31 Desember 2028 23:59:59 UTC
    startLabel: "1 Desember 2026",
    endLabel: "31 Desember 2028",
  },
  limitsUsd: {
    minPurchaseUsd: 25,
    maxPurchaseUsdPerWalletPerBatch: 10000,
    totalBatches: 10,
    batchVoinAllocation: "15600000",
    totalPresaleVoinAllocation: "156000000",
  },
  supportedChains: {
    bscMainnet: {
      chainId: 56,
      chainIdHex: "0x38",
      name: "BNB Smart Chain",
      explorerUrl: "https://bscscan.com",
    },
    bscTestnet: {
      chainId: 97,
      chainIdHex: "0x61",
      name: "BNB Smart Chain Testnet",
      explorerUrl: "https://testnet.bscscan.com",
    },
  },
};

function buildUpstreamUrl(requestUrl, upstreamBase) {
  const incomingUrl = new URL(requestUrl);
  const baseUrl = new URL(upstreamBase);

  const cleanBasePath = baseUrl.pathname.replace(/\/+$/, "");
  const cleanIncomingPath = incomingUrl.pathname.startsWith("/")
    ? incomingUrl.pathname
    : `/${incomingUrl.pathname}`;

  baseUrl.pathname = `${cleanBasePath}${cleanIncomingPath}` || "/";
  baseUrl.search = incomingUrl.search;
  return baseUrl.toString();
}

function buildForwardHeaders(request, apiToken) {
  const headers = new Headers();

  for (const [key, value] of request.headers.entries()) {
    const lower = key.toLowerCase();
    if (lower !== "host" && lower !== "content-length") {
      headers.set(key, value);
    }
  }

  if (!headers.has("Authorization") && apiToken) {
    headers.set("Authorization", `Bearer ${apiToken}`);
  }

  return headers;
}

function withStandardHeaders(response, extraHeaders = {}) {
  const headers = new Headers(response.headers);
  headers.set("X-VOIN-Gateway", "cloudflare-worker");
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Token");

  for (const [k, v] of Object.entries(extraHeaders)) {
    headers.set(k, v);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request, env, ctx) {
    const method = (request.method || "GET").toUpperCase();

    if (method === "OPTIONS") {
      return withStandardHeaders(new Response(null, { status: 204 }));
    }

    const url = new URL(request.url);
    const upstreamBase = (env.VOIN_GATEWAY_URL || DEFAULT_GATEWAY_URL || "").trim();
    const apiToken = (env.API_TOKEN || DEFAULT_API_TOKEN || "").trim();

    if (url.pathname === "/health") {
      return withStandardHeaders(
        new Response(
          JSON.stringify({
            status: "OPERATIONAL",
            message: "VOIN Worker gateway active",
            upstreamConfigured: Boolean(upstreamBase),
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }
        )
      );
    }

    if (url.pathname === "/presale/config" && method === "GET") {
      return withStandardHeaders(
        new Response(
          JSON.stringify({
            status: "OK",
            presale: {
              ...PRESALE_PUBLIC_CONFIG,
              treasuryAddress: (env.TREASURY_ADDRESS || PRESALE_PUBLIC_CONFIG.treasuryAddress).trim(),
              contracts: {
                voinToken: (env.VOIN_TOKEN_ADDRESS || "").trim(),
                voinPresale: (env.VOIN_PRESALE_CONTRACT || "").trim(),
                voinVesting: (env.VOIN_VESTING_CONTRACT || "").trim(),
              },
            },
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }
        )
      );
    }

    if (!upstreamBase) {
      return withStandardHeaders(
        new Response(
          JSON.stringify({
            status: "MISCONFIGURED",
            message: "VOIN_GATEWAY_URL belum dikonfigurasi pada environment Worker",
          }),
          {
            status: 502,
            headers: { "Content-Type": "application/json" },
          }
        )
      );
    }

    const targetUrl = buildUpstreamUrl(request.url, upstreamBase);
    const forwardHeaders = buildForwardHeaders(request, apiToken);

    const init = {
      method,
      headers: forwardHeaders,
    };

    if (method !== "GET" && method !== "HEAD") {
      const rawBody = await request.arrayBuffer();
      if (rawBody.byteLength > 0) {
        init.body = rawBody;
      }
    }

    try {
      const upstreamResponse = await fetch(targetUrl, init);
      const responseBody = await upstreamResponse.arrayBuffer();

      return withStandardHeaders(
        new Response(responseBody, {
          status: upstreamResponse.status,
          statusText: upstreamResponse.statusText,
          headers: upstreamResponse.headers,
        })
      );
    } catch (error) {
      return withStandardHeaders(
        new Response(
          JSON.stringify({
            status: "BAD_GATEWAY",
            message: "Gagal menghubungi VOIN Gateway / Node upstream",
            detail: error instanceof Error ? error.message : String(error),
          }),
          {
            status: 502,
            headers: { "Content-Type": "application/json" },
          }
        )
      );
    }
  },
};
