from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

import httpx


def validate_url(url: str, allowed_hosts=()):
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Use an HTTP(S) URL without embedded credentials, query, or fragment")
    host = parsed.hostname.lower()
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if allowed_hosts is not None and not loopback and host not in allowed_hosts:
        raise ValueError("Model endpoint must be loopback or an explicitly allowed internal hostname")
    if allowed_hosts is None and parsed.scheme != "https" and not loopback:
        raise ValueError("Remote backends require HTTPS; use the company's internal HTTPS endpoint")
    return url.rstrip("/")


class Client:
    def __init__(self, url: str, token=""):
        self.url = validate_url(url, allowed_hosts=None)
        self.token = token

    def request(self, method, path, body=None):
        try:
            with httpx.Client(timeout=45, trust_env=False, follow_redirects=False) as client:
                response = client.request(method, self.url + path, json=body,
                                          headers={"Authorization": "Bearer " + self.token} if self.token else {})
        except httpx.HTTPError as exc:
            raise RuntimeError("Cannot contact the internal OpenSAST backend") from exc
        if response.is_error:
            try:
                detail = response.json().get("detail", "Request failed")
            except ValueError:
                detail = "Request failed"
            raise RuntimeError(f"HTTP {response.status_code}: {detail}")
        return response.json()
