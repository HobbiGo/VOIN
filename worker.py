import io
from urllib.parse import urlparse
from js import Response

from security.gateway import VOINSecurityGateway
from security.api import VOINSecurityAPIEngine
from security.integration import VOINSecurityIntegration
from security.dashboard import VOINSecurityDashboard
from security.alert import VOINAlertEngine
from security.audit import VOINAuditEngine
from security.monitor import VOINSecurityMonitor
from security.rate_limit import VOINRateLimitEngine
from security.storage import VOINStorageEngine
from security.d1_storage import VOIND1StorageEngine
from security.d1_rate_limit import VOIND1RateLimitEngine

try:
    from blockchain.transaction_verifier import (
        BlockchainTransactionVerifier,
        DEFAULT_RPC_URL,
        DEFAULT_TREASURY_ADDRESS,
        VerificationResult,
    )
except Exception:
    BlockchainTransactionVerifier = None
    DEFAULT_RPC_URL = "https://data-seed-prebsc-1-s1.binance.org:8545/"
    DEFAULT_TREASURY_ADDRESS = "0xAEb22359588A50e6F746004E66418Eb2c978dAA2"
    VerificationResult = None


def build_presale_verifier(env):
    if BlockchainTransactionVerifier is None:
        return None

    rpc_url = getattr(env, "BSC_RPC_URL", None) or DEFAULT_RPC_URL
    presale_contract = getattr(env, "VOIN_PRESALE_CONTRACT", None) or ""
    treasury_address = getattr(env, "TREASURY_ADDRESS", None) or DEFAULT_TREASURY_ADDRESS
    raw_chain_id = getattr(env, "EXPECTED_CHAIN_ID", None)
    expected_chain_id = int(raw_chain_id) if raw_chain_id not in (None, "") else None

    return BlockchainTransactionVerifier(
        rpc_url=rpc_url,
        presale_contract_address=presale_contract,
        treasury_address=treasury_address,
        expected_chain_id=expected_chain_id,
    )


def verify_presale_tx_hash(
    env,
    tx_hash: str,
    expected_buyer: str | None = None,
    existing_batch_spent_usd_wei: int = 0,
) -> dict:
    verifier = build_presale_verifier(env)
    if verifier is None:
        return {
            "valid": False,
            "tx_hash": tx_hash,
            "reason": "BlockchainTransactionVerifier unavailable in current runtime",
        }

    result = verifier.verify_presale_transaction(
        tx_hash=tx_hash,
        expected_buyer=expected_buyer,
        existing_batch_spent_usd_wei=existing_batch_spent_usd_wei,
    )
    return {
        "valid": result.valid,
        "tx_hash": result.tx_hash,
        "chain_id": result.chain_id,
        "block_number": result.block_number,
        "buyer": result.buyer,
        "payment_token": result.payment_token,
        "amount_paid_raw": result.amount_paid_raw,
        "usd_value_wei": result.usd_value_wei,
        "voin_amount_wei": result.voin_amount_wei,
        "batch_id": result.batch_id,
        "timestamp": result.timestamp,
        "reason": result.reason,
    }


def build_gateway(env):
    api_token = getattr(env, "API_TOKEN", None) or "voin-secret-token-yang-sangat-panjang-dan-aman-123"
    host = getattr(env, "GATEWAY_HOST", None) or "0.0.0.0"
    port = int(getattr(env, "GATEWAY_PORT", None) or 5000)

    max_attempts = int(getattr(env, "MAX_ATTEMPTS", None) or 10)
    window_seconds = int(getattr(env, "WINDOW_SECONDS", None) or 60)
    cooldown_seconds = int(getattr(env, "COOLDOWN_SECONDS", None) or 300)
    expiry_seconds = int(getattr(env, "EXPIRY_SECONDS", None) or 300)

    d1_db = getattr(env, "DB", None)
    if d1_db is not None:
        storage = VOIND1StorageEngine(database=d1_db)
        rate_limit_engine = VOIND1RateLimitEngine(
            database=d1_db,
            max_attempts=max_attempts,
            window_seconds=window_seconds,
            cooldown_seconds=cooldown_seconds,
        )
    else:
        db_path = getattr(env, "DATABASE_PATH", None) or "/tmp/voin_security.db"
        storage = VOINStorageEngine(database_path=db_path)
        rate_limit_engine = VOINRateLimitEngine(
            storage=storage,
            max_attempts=max_attempts,
            window_seconds=window_seconds,
            cooldown_seconds=cooldown_seconds,
        )

    audit_engine = VOINAuditEngine(storage=storage)
    alert_engine = VOINAlertEngine(storage=storage)
    monitor_engine = VOINSecurityMonitor(audit_engine=audit_engine)

    dashboard = VOINSecurityDashboard(
        storage=storage,
        audit_engine=audit_engine,
        monitor_engine=monitor_engine,
        alert_engine=alert_engine,
        rate_limit_engine=rate_limit_engine,
    )

    api_engine = VOINSecurityAPIEngine(
        dashboard=dashboard,
        api_token=api_token,
        alert_engine=alert_engine,
        monitor_engine=monitor_engine,
        rate_limit_engine=rate_limit_engine,
    )

    security_integration = VOINSecurityIntegration(
        expiry_seconds=expiry_seconds,
        max_attempts=max_attempts,
        window_seconds=window_seconds,
        cooldown_seconds=cooldown_seconds,
    )

    return VOINSecurityGateway(
        api_engine=api_engine,
        security_integration=security_integration,
        host=host,
        port=port,
    )


async def _read_request_body_bytes(request) -> bytes:
    method = (request.method or "GET").upper()
    if method in ("GET", "HEAD"):
        return b""
    text_body = await request.text()
    if not text_body:
        return b""
    return text_body.encode("utf-8")


async def on_fetch(request, env, ctx):
    gateway = build_gateway(env)

    parsed = urlparse(str(request.url))
    method = (request.method or "GET").upper()
    path = parsed.path or "/"
    query_string = parsed.query or ""

    auth_header = request.headers.get("Authorization") or ""
    content_type = request.headers.get("Content-Type") or ""
    body_bytes_in = await _read_request_body_bytes(request)

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string,
        "HTTP_AUTHORIZATION": auth_header,
        "CONTENT_TYPE": content_type,
        "CONTENT_LENGTH": str(len(body_bytes_in)),
        "wsgi.input": io.BytesIO(body_bytes_in),
        "wsgi.url_scheme": parsed.scheme or "https",
        "SERVER_NAME": parsed.hostname or "localhost",
        "SERVER_PORT": str(parsed.port or (443 if (parsed.scheme or "https") == "https" else 80)),
    }

    response_data = {
        "status": "500 Internal Server Error",
        "headers": [],
    }

    def start_response(status, headers, exc_info=None):
        response_data["status"] = status
        response_data["headers"] = headers

    body_chunks = gateway.application(environ, start_response)
    body_bytes_out = b"".join(body_chunks)
    status_code = int(str(response_data["status"]).split(" ")[0])

    return Response.new(
        body_bytes_out,
        status=status_code,
        headers=dict(response_data["headers"]),
    )
