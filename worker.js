const DEFAULT_GATEWAY_URL = "http://127.0.0.1:5000";
const DEFAULT_API_TOKEN = "voin-secret-token-yang-sangat-panjang-dan-aman-123";

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
          headers: { "Content-Type": "application/json" },
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
          headers: { "Content-Type": "application/json" },
        }
      );
    }
  },
};
