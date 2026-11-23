const DEFAULT_GATEWAY_URL = "http://127.0.0.1:5000";
const DEFAULT_API_TOKEN = "voin-secret-token-yang-sangat-panjang-dan-aman-123";

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

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upstreamBase = env.VOIN_GATEWAY_URL || DEFAULT_GATEWAY_URL;
    const apiToken = env.API_TOKEN || DEFAULT_API_TOKEN;

    if (url.pathname === "/health") {
      return new Response(
        JSON.stringify({
          status: "OPERATIONAL",
          message: "VOIN Worker gateway active",
          upstreamConfigured: Boolean(env.VOIN_GATEWAY_URL),
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-VOIN-Gateway": "cloudflare-worker",
          },
        }
      );
    }

    if (url.pathname === "/presale/config" && (request.method || "GET").toUpperCase() === "GET") {
      return new Response(
        JSON.stringify({
          status: "OK",
          presale: {
            ...PRESALE_PUBLIC_CONFIG,
            treasuryAddress: env.TREASURY_ADDRESS || PRESALE_PUBLIC_CONFIG.treasuryAddress,
            contracts: {
              voinToken: env.VOIN_TOKEN_ADDRESS || "",
              voinPresale: env.VOIN_PRESALE_CONTRACT || "",
              voinVesting: env.VOIN_VESTING_CONTRACT || "",
            },
          },
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "X-VOIN-Gateway": "cloudflare-worker",
          },
        }
      );
    }

    const method = (request.method || "GET").toUpperCase();
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

      const responseHeaders = new Headers(upstreamResponse.headers);
      responseHeaders.set("X-VOIN-Gateway", "cloudflare-worker");

      return new Response(responseBody, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers: responseHeaders,
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          status: "BAD_GATEWAY",
          message: "Gagal menghubungi VOIN Gateway / Node upstream",
          detail: error instanceof Error ? error.message : String(error),
        }),
        {
          status: 502,
          headers: {
            "Content-Type": "application/json",
            "X-VOIN-Gateway": "cloudflare-worker",
          },
        }
      );
    }
  },
};
