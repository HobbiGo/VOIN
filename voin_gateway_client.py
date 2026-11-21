import os
from urllib.parse import urljoin
import requests

DEFAULT_GATEWAY_URL = "http://127.0.0.1:5000"


def get_gateway_url() -> str:
    """Ambil VOIN_GATEWAY_URL dari environment (default ke node lokal)."""
    raw_url = os.getenv("VOIN_GATEWAY_URL") or DEFAULT_GATEWAY_URL
    return raw_url.strip().rstrip("/")


def build_endpoint_url(path: str, base_url: str | None = None) -> str:
    """Gabungkan URL dasar gateway dengan path endpoint."""
    root = (base_url or get_gateway_url()).rstrip("/") + "/"
    clean_path = path.lstrip("/")
    return urljoin(root, clean_path)


def call_gateway(
    method: str,
    path: str,
    *,
    json_data: dict | None = None,
    params: dict | None = None,
    api_token: str | None = None,
    timeout: int = 15,
):
    """Kirim request ke endpoint VOIN Gateway."""
    url = build_endpoint_url(path)
    token = api_token if api_token is not None else os.getenv("VOIN_API_TOKEN", "")

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    return requests.request(
        method=method.upper(),
        url=url,
        json=json_data,
        params=params,
        headers=headers,
        timeout=timeout,
    )
