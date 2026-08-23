import argparse
import base64
import html
import ipaddress
import json
import os
import re
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

import requests
import geoip2.database

SUPPORTED_SCHEMES = {"vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "hy2"}
SHARE_LINK_RE = re.compile(
    rf"\b(?:{'|'.join(sorted(SUPPORTED_SCHEMES))})://[^\s\"'<>`\\\]\[{{}}]+",
    re.IGNORECASE,
)
DEFAULT_GEOIP_URL = "https://git.io/GeoLite2-Country.mmdb"
COUNTRY_REPLACEMENTS = {
    "en": {
        "Federal Republic of Germany": "Germany",
        "Virgin Islands, U.S.": "Virgin Islands",
    }
}
HEADER_PREFIXES = ("#profile-", "#announce:")
UNSTABLE_HEADER_LINES = [
    "#profile-title: penetrate unstable",
    "#profile-web-page-url: https://penetratevpn.github.io",
    "#announce: Telegram: @penetratevpn (current sub: unstable)",
]


@dataclass(frozen=True)
class CheckResult:
    uri: str
    country_name: str
    country_code: str
    real_ip: str
    latency_ms: int
    protocol: str
    old_remark: str
    is_working: bool


class Progress:
    def __init__(self, total: int):
        self.total = total
        self.done = 0
        self.lock = threading.Lock()

    def next(self) -> int:
        with self.lock:
            self.done += 1
            return self.done


def read_text_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()


def split_default_file(path: Path) -> tuple[list[str], list[str]]:
    headers: list[str] = []
    links: list[str] = []
    for line in read_text_lines(path):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(HEADER_PREFIXES):
            headers.append(stripped)
        else:
            links.append(stripped)
    return headers, links


def write_default_file(path: Path, headers: list[str], links: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(headers + links) + "\n"
    path.write_text(content, encoding="utf-8")


def get_nested(obj: object, path: list[object]) -> object | None:
    current = obj
    for key in path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list) and isinstance(key, int) and 0 <= key < len(current):
            current = current[key]
        else:
            return None
    return current


def decode_base64_urlsafe(value: str) -> str:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("utf-8")).decode("utf-8")


def encode_base64_nopad(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("utf-8").rstrip("=")


def parse_json_objects(json_str: str) -> list[object]:
    try:
        data = json.loads(json_str)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        objects = []
        stack: list[str] = []
        start_index: int | None = None
        for index, char in enumerate(json_str):
            if char == "{":
                if not stack:
                    start_index = index
                stack.append(char)
            elif char == "}" and stack:
                stack.pop()
                if not stack and start_index is not None:
                    try:
                        objects.append(json.loads(json_str[start_index : index + 1]))
                    except json.JSONDecodeError:
                        pass
                    start_index = None
        return objects


def build_url_from_outbound(outbound: dict, remarks: str, urls: list[str]) -> None:
    proto = outbound.get("protocol")
    if not proto:
        return

    tag = urllib.parse.quote(remarks or outbound.get("tag") or proto)
    params: dict[str, str] = {}
    base = ""

    if proto == "shadowsocks":
        servers = get_nested(outbound, ["settings", "servers"]) or []
        if not isinstance(servers, list):
            return
        for server in servers:
            method = server.get("method", "")
            password = server.get("password", "")
            address = server.get("address", "")
            port = server.get("port", "")
            auth = encode_base64_nopad(f"{method}:{password}")
            urls.append(f"ss://{auth}@{address}:{port}#{tag}")
        return

    if proto == "hysteria":
        # NOTE: this was previously not handled at all - hysteria outbounds
        # were silently dropped when converting a JSON config back to a link.
        settings = outbound.get("settings", {}) or {}
        address = settings.get("address")
        port = settings.get("port")
        stream = outbound.get("streamSettings", {}) or {}
        tls = stream.get("tlsSettings", {}) if isinstance(stream, dict) else {}
        hy = stream.get("hysteriaSettings", {}) if isinstance(stream, dict) else {}
        auth = hy.get("auth", "")
        if not (address and port and auth):
            return
        hy_params: dict[str, str] = {}
        if tls.get("serverName"):
            hy_params["sni"] = str(tls["serverName"])
        if isinstance(tls.get("alpn"), list):
            hy_params["alpn"] = ",".join(str(item) for item in tls["alpn"])
        if tls.get("allowInsecure"):
            hy_params["insecure"] = "1"
        query_string = urllib.parse.urlencode(hy_params)
        urls.append(f"hysteria2://{urllib.parse.quote(str(auth))}@{address}:{port}?{query_string}#{tag}")
        return

    if proto in {"vmess", "vless"}:
        vnext = get_nested(outbound, ["settings", "vnext", 0])
        user = get_nested(outbound, ["settings", "vnext", 0, "users", 0])
        if isinstance(vnext, dict) and isinstance(user, dict):
            base = f"{proto}://{user.get('id')}@{vnext.get('address')}:{vnext.get('port')}"
            params["encryption"] = user.get("encryption") or user.get("security") or ("auto" if proto == "vmess" else "none")
            if user.get("flow"):
                params["flow"] = str(user["flow"])

    if proto == "trojan":
        server = get_nested(outbound, ["settings", "servers", 0])
        if isinstance(server, dict):
            password = urllib.parse.quote(str(server.get("password", "")))
            base = f"trojan://{password}@{server.get('address')}:{server.get('port')}"

    if not base:
        return

    stream = outbound.get("streamSettings", {})
    tls = stream.get("tlsSettings", {}) if isinstance(stream, dict) else {}
    reality = stream.get("realitySettings", {}) if isinstance(stream, dict) else {}

    if stream.get("security"):
        params["security"] = str(stream["security"])
    if tls.get("allowInsecure"):
        params["allowInsecure"] = "1"
    if isinstance(tls.get("alpn"), list):
        params["alpn"] = ",".join(str(item) for item in tls["alpn"])
    elif isinstance(reality.get("alpn"), list):
        # reality configs sometimes carry alpn here instead of tlsSettings
        params["alpn"] = ",".join(str(item) for item in reality["alpn"])
    if tls.get("serverName"):
        params["sni"] = str(tls["serverName"])
    elif reality.get("serverName"):
        params["sni"] = str(reality["serverName"])
    if tls.get("fingerprint"):
        params["fp"] = str(tls["fingerprint"])
    elif reality.get("fingerprint"):
        # previously fp was only ever read from tlsSettings, so it was
        # silently dropped for every reality (tlsSettings-less) config
        params["fp"] = str(reality["fingerprint"])
    if reality.get("publicKey"):
        params["pbk"] = str(reality["publicKey"])
    if reality.get("shortId"):
        params["sid"] = str(reality["shortId"])
    if reality.get("spiderX"):
        params["spx"] = str(reality["spiderX"])

    network = str(stream.get("network") or "tcp")
    if network == "splithttp":
        network = "xhttp"
    params["type"] = network

    host = ""
    path = ""
    if network == "ws":
        host = get_nested(stream, ["wsSettings", "headers", "Host"]) or ""
        path = get_nested(stream, ["wsSettings", "path"]) or ""
    elif network == "xhttp":
        settings = stream.get("xhttpSettings") or stream.get("splithttpSettings") or {}
        host_value = settings.get("host", "")
        host = host_value[0] if isinstance(host_value, list) and host_value else host_value
        path = settings.get("path", "")
        if settings.get("mode"):
            params["mode"] = str(settings["mode"])
    elif network == "httpupgrade":
        settings = stream.get("httpupgradeSettings", {})
        host_value = settings.get("host", "")
        host = host_value[0] if isinstance(host_value, list) and host_value else host_value
        path = settings.get("path", "")
    elif network == "http":
        settings = stream.get("httpSettings", {})
        host_value = settings.get("host", "")
        host = host_value[0] if isinstance(host_value, list) and host_value else host_value
        path = settings.get("path", "")
    elif network == "grpc":
        # previously missing entirely - serviceName/mode were silently dropped
        settings = stream.get("grpcSettings", {}) if isinstance(stream, dict) else {}
        if settings.get("serviceName"):
            params["serviceName"] = str(settings["serviceName"])
        if settings.get("multiMode"):
            params["mode"] = "multi"
    elif network == "tcp" and get_nested(stream, ["tcpSettings", "header", "type"]) == "http":
        request = get_nested(stream, ["tcpSettings", "header", "request"]) or {}
        hosts = get_nested(request, ["headers", "Host"])
        paths = request.get("path") if isinstance(request, dict) else None
        host = hosts[0] if isinstance(hosts, list) and hosts else ""
        path = paths[0] if isinstance(paths, list) and paths else ""
        params["headerType"] = "http"

    if host:
        params["host"] = str(host)
    if path:
        params["path"] = str(path)

    query_string = urllib.parse.urlencode(params)
    urls.append(f"{base}?{query_string}#{tag}")


def handle_wrapped_config(obj: dict, urls: list[str]) -> bool:
    if "config" not in obj or not isinstance(obj["config"], str):
        return False
    try:
        cfg = json.loads(obj["config"])
    except json.JSONDecodeError:
        return False

    root_address = obj.get("address", "")
    root_id = obj.get("server_id", "")
    remarks = obj.get("remarks", "")
    outbounds = cfg.get("outbounds")
    if not isinstance(outbounds, list):
        return False

    for outbound in outbounds:
        vnext = get_nested(outbound, ["settings", "vnext", 0])
        if isinstance(vnext, dict) and not vnext.get("address") and root_address:
            vnext["address"] = root_address

        user = get_nested(outbound, ["settings", "vnext", 0, "users", 0])
        if isinstance(user, dict) and not user.get("id") and root_id:
            user["id"] = root_id

        build_url_from_outbound(outbound, remarks, urls)
    return True


def convert_json_to_urls(json_str: str) -> list[str]:
    urls: list[str] = []
    json_str = json_str.strip()
    if not json_str:
        return urls

    for obj in parse_json_objects(json_str):
        if not isinstance(obj, dict):
            continue
        if handle_wrapped_config(obj, urls):
            continue

        config_type = obj.get("configType")
        if config_type == "SHADOWSOCKS" and obj.get("method") and obj.get("password") and obj.get("server"):
            auth = encode_base64_nopad(f"{obj['method']}:{obj['password']}")
            tag = urllib.parse.quote(obj.get("remarks", ""))
            urls.append(f"ss://{auth}@{obj['server']}:{obj.get('serverPort')}#{tag}")
            continue

        if config_type == "VLESS" and obj.get("password") and obj.get("server"):
            params = {
                "encryption": obj.get("method", "none"),
                "security": obj.get("security", ""),
                "flow": obj.get("flow", ""),
                "type": obj.get("network", ""),
                "headerType": obj.get("headerType", ""),
                "host": obj.get("host", ""),
                "path": obj.get("path", ""),
                "sni": obj.get("sni", ""),
                "fp": obj.get("fingerPrint", ""),
                "pbk": obj.get("publicKey", ""),
                "sid": obj.get("shortId", ""),
            }
            if isinstance(obj.get("alpn"), list):
                params["alpn"] = ",".join(obj["alpn"])
            elif obj.get("alpn"):
                params["alpn"] = obj["alpn"]
            if obj.get("allowInsecure") is not None:
                params["allowInsecure"] = "1" if obj["allowInsecure"] else "0"

            query = urllib.parse.urlencode({key: value for key, value in params.items() if value != ""})
            tag = urllib.parse.quote(obj.get("remarks", ""))
            urls.append(f"vless://{obj['password']}@{obj['server']}:{obj.get('serverPort')}?{query}#{tag}")
            continue

        outbounds = obj.get("outbounds") or get_nested(obj, ["fullConfig", "outbounds"]) or []
        if isinstance(outbounds, list):
            for outbound in outbounds:
                if isinstance(outbound, dict):
                    build_url_from_outbound(outbound, obj.get("remarks", ""), urls)

    return urls


def looks_like_base64(value: str) -> bool:
    compact = "".join(value.strip().split())
    if len(compact) < 16:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact) is not None


def decode_base64_text(value: str) -> str | None:
    compact = "".join(value.strip().split())
    if not looks_like_base64(compact):
        return None
    padding = "=" * (-len(compact) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder((compact + padding).encode("utf-8"))
            text = decoded.decode("utf-8")
        except Exception:
            continue
        if any(marker in text for marker in ("://", "{", "[", "\n")):
            return text
    return None


def clean_share_link(link: str) -> str:
    return html.unescape(link).strip().rstrip(".,;)")


def extract_json_strings(obj: object) -> list[str]:
    strings: list[str] = []
    if isinstance(obj, str):
        strings.append(obj)
    elif isinstance(obj, dict):
        for value in obj.values():
            strings.extend(extract_json_strings(value))
    elif isinstance(obj, list):
        for value in obj:
            strings.extend(extract_json_strings(value))
    return strings


def extract_subscription_links(text: str, depth: int = 0) -> list[str]:
    if depth > 3:
        return []

    links = [clean_share_link(match.group(0)) for match in SHARE_LINK_RE.finditer(text)]
    links.extend(convert_json_to_urls(text))

    for obj in parse_json_objects(text):
        for value in extract_json_strings(obj):
            if value != text:
                links.extend(extract_subscription_links(value, depth + 1))

    decoded = decode_base64_text(text)
    if decoded and decoded != text:
        links.extend(extract_subscription_links(decoded, depth + 1))

    return [link for link in links if urllib.parse.urlparse(link).scheme.lower() in SUPPORTED_SCHEMES]


def add_query_param(url: str, key: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    existing_keys = {item_key.lower() for item_key, _item_value in query}
    if key.lower() not in existing_keys:
        query.append((key, value))
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(query)))


def happ_headers(hwid: str | None) -> dict[str, str]:
    headers = {
        "User-Agent": "Happ/4.10.2/ios/2605221402666",
        "Accept": "*/*",
        "Accept-Language": "en-GB,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "X-Device-OS": "iOS",
        "X-Device-Locale": "en",
        "X-Ver-OS": "16.7.15",
        "X-App-Version": "4.10.2",
        "X-Device-model": "iPhone X",
    }
    if hwid:
        headers["X-HWID"] = hwid
    return headers


def fetch_subscription(url: str, hwid: str | None, timeout: float = 15.0) -> str:
    response = requests.get(url, headers=happ_headers(hwid), timeout=timeout)
    if hwid and response.status_code in {400, 403, 404}:
        retry_url = add_query_param(url, "hwid", hwid)
        if retry_url != url:
            retry = requests.get(retry_url, headers=happ_headers(hwid), timeout=timeout)
            if retry.ok or not response.ok:
                response = retry
    response.raise_for_status()
    response.encoding = response.encoding or "utf-8"
    return response.text


def endpoint_key(uri: str) -> str | None:
    try:
        parsed = urllib.parse.urlparse(uri)
    except Exception:
        return None
    if parsed.scheme.lower() == "vmess" and "@" not in uri.removeprefix("vmess://"):
        try:
            data, _remark = parse_vmess_uri(uri)
            host = data.get("add") or data.get("address")
            port = int(data.get("port") or default_port("vmess"))
            if host:
                return f"vmess://{str(host).lower()}:{port}"
        except Exception:
            return None
    if not parsed.scheme or not parsed.netloc:
        return None
    host = parsed.hostname
    if not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    return f"{parsed.scheme.lower()}://{host.lower()}:{port or default_port(parsed.scheme)}"


def default_port(scheme: str) -> int:
    return 443 if scheme.lower() in {"vless", "vmess", "trojan"} else 0


def dedupe_links(links: list[str], by_endpoint: bool = True) -> list[str]:
    seen = set()
    result = []
    for link in links:
        key = endpoint_key(link) if by_endpoint else link
        key = key or link
        if key in seen:
            continue
        seen.add(key)
        result.append(link)
    return result


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def get_unicode_flag(country_code: str) -> str:
    if not country_code or country_code == "UN":
        return "🌐"
    try:
        return "".join(chr(127397 + ord(char)) for char in country_code.upper())
    except Exception:
        return "🌐"


def decode_fragment(fragment: str) -> str:
    return urllib.parse.unquote(fragment or "")


def parse_vmess_uri(uri: str) -> tuple[dict, str]:
    body = uri.removeprefix("vmess://")
    if "@" not in body:
        data = json.loads(decode_base64_urlsafe(body.split("#", 1)[0]))
        return data, urllib.parse.unquote(body.split("#", 1)[1]) if "#" in body else data.get("ps", "")

    parsed = urllib.parse.urlparse(uri)
    query = urllib.parse.parse_qs(parsed.query)
    return {
        "id": urllib.parse.unquote(parsed.username or ""),
        "add": parsed.hostname,
        "port": parsed.port or 443,
        "aid": query.get("alterId", query.get("aid", ["0"]))[0],
        "scy": query.get("encryption", query.get("scy", ["auto"]))[0],
        "net": query.get("type", ["tcp"])[0],
        "tls": query.get("security", ["none"])[0],
        "sni": query.get("sni", [parsed.hostname or ""])[0],
        "host": query.get("host", [""])[0],
        "path": query.get("path", [""])[0],
        "allowInsecure": query.get("allowInsecure", [""])[0],
        "alpn": query.get("alpn", [""])[0],
        "fp": query.get("fp", ["chrome"])[0],
        "headerType": query.get("headerType", [""])[0],
        "serviceName": query.get("serviceName", [""])[0],
        "mode": query.get("mode", [""])[0],
    }, decode_fragment(parsed.fragment)


def normalize_transport(transport: str) -> str:
    aliases = {"": "tcp", "raw": "tcp", "websocket": "ws", "splithttp": "xhttp"}
    return aliases.get(transport.lower(), transport.lower())


def build_singbox_tls(query: dict[str, list[str]], server_host: str) -> dict | None:
    """sing-box TLS object shared by vless/vmess/trojan outbounds."""
    security = query.get("security", ["none"])[0] or "none"
    if security not in {"tls", "reality"}:
        return None
    sni = query.get("sni", [server_host])[0] or server_host
    fingerprint = query.get("fp", ["chrome"])[0] or "chrome"

    tls: dict = {"enabled": True, "server_name": sni}
    if query.get("allowInsecure"):
        tls["insecure"] = query["allowInsecure"][0] in {"1", "true", "True"}
    if query.get("alpn"):
        tls["alpn"] = query["alpn"][0].split(",")
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": query.get("pbk", [""])[0],
            "short_id": query.get("sid", [""])[0],
        }
    return tls


def build_singbox_transport(query: dict[str, list[str]], server_host: str) -> dict | None:
    """sing-box V2Ray-transport object. Returns None for plain tcp."""
    transport = normalize_transport(query.get("type", ["tcp"])[0] or "tcp")
    if transport in {"tcp", ""}:
        return None
    if transport == "ws":
        return {
            "type": "ws",
            "path": query.get("path", ["/"])[0] or "/",
            "headers": {"Host": query.get("host", [server_host])[0] or server_host},
        }
    if transport == "grpc":
        return {"type": "grpc", "service_name": query.get("serviceName", [""])[0]}
    if transport == "httpupgrade":
        return {
            "type": "httpupgrade",
            "path": query.get("path", ["/"])[0] or "/",
            "host": query.get("host", [server_host])[0] or server_host,
        }
    if transport == "http":
        return {
            "type": "http",
            "path": query.get("path", ["/"])[0] or "/",
            "host": [query.get("host", [server_host])[0] or server_host],
        }
    # xhttp/splithttp and the legacy tcp+http-header camouflage don't have a
    # matching sing-box transport - these links will fail the live check and
    # fall through to the unstable file (with DNS+geoip still attempted).
    raise ValueError(f"sing-box: unsupported transport '{transport}'")


def generate_vless_outbound(parsed: urllib.parse.ParseResult) -> dict:
    user_id = urllib.parse.unquote(parsed.username or "")
    server_host = parsed.hostname
    server_port = parsed.port or 443
    if not user_id or not server_host:
        raise ValueError("invalid VLESS URI: missing user id or host")
    query = urllib.parse.parse_qs(parsed.query)
    outbound: dict = {
        "type": "vless",
        "tag": "proxy",
        "server": server_host,
        "server_port": server_port,
        "uuid": user_id,
    }
    flow = query.get("flow", [""])[0]
    if flow:
        outbound["flow"] = flow
    tls = build_singbox_tls(query, server_host)
    if tls:
        outbound["tls"] = tls
    transport = build_singbox_transport(query, server_host)
    if transport:
        outbound["transport"] = transport
    return outbound


def generate_trojan_outbound(parsed: urllib.parse.ParseResult) -> dict:
    password = urllib.parse.unquote(parsed.username or "")
    server_host = parsed.hostname
    server_port = parsed.port or 443
    if not password or not server_host:
        raise ValueError("invalid Trojan URI: missing password or host")
    query = urllib.parse.parse_qs(parsed.query)
    outbound: dict = {
        "type": "trojan",
        "tag": "proxy",
        "server": server_host,
        "server_port": server_port,
        "password": password,
    }
    tls = build_singbox_tls(query, server_host) or {"enabled": True, "server_name": server_host}
    outbound["tls"] = tls
    transport = build_singbox_transport(query, server_host)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_shadowsocks_userinfo(parsed: urllib.parse.ParseResult) -> tuple[str, str]:
    userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else parsed.netloc
    userinfo = urllib.parse.unquote(userinfo)
    if ":" not in userinfo:
        userinfo = decode_base64_urlsafe(userinfo)
    method, password = userinfo.split(":", 1)
    return method, password


def generate_shadowsocks_outbound(parsed: urllib.parse.ParseResult) -> dict:
    server_host = parsed.hostname
    server_port = parsed.port
    if not server_host or not server_port:
        raise ValueError("invalid Shadowsocks URI: missing host or port")
    method, password = parse_shadowsocks_userinfo(parsed)
    if not method or not password:
        raise ValueError("invalid Shadowsocks URI: missing method or password")
    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": server_host,
        "server_port": server_port,
        "method": method,
        "password": password,
    }


def generate_vmess_outbound(uri: str) -> dict:
    data, _remark = parse_vmess_uri(uri)
    server_host = data.get("add") or data.get("address")
    server_port = int(data.get("port") or 443)
    user_id = data.get("id")
    if not server_host or not user_id:
        raise ValueError("invalid VMess URI: missing id or host")
    query = {
        "type": [data.get("net") or data.get("type") or "tcp"],
        "security": [data.get("tls") or "none"],
        "sni": [data.get("sni") or server_host],
        "host": [data.get("host") or ""],
        "path": [data.get("path") or ""],
        "allowInsecure": [str(data.get("allowInsecure") or "")],
        "alpn": [data.get("alpn") or ""],
        "fp": [data.get("fp") or "chrome"],
        "serviceName": [data.get("serviceName") or ""],
    }
    outbound: dict = {
        "type": "vmess",
        "tag": "proxy",
        "server": server_host,
        "server_port": server_port,
        "uuid": user_id,
        "security": data.get("scy") or data.get("security") or "auto",
        "alter_id": int(data.get("aid") or 0),
    }
    tls = build_singbox_tls(query, server_host)
    if tls:
        outbound["tls"] = tls
    transport = build_singbox_transport(query, server_host)
    if transport:
        outbound["transport"] = transport
    return outbound


def generate_hysteria2_outbound(parsed: urllib.parse.ParseResult) -> dict:
    password = urllib.parse.unquote(parsed.username or "")
    server_host = parsed.hostname
    server_port = parsed.port or 443
    if not password or not server_host:
        raise ValueError("invalid Hysteria2 URI: missing password or host")
    query = urllib.parse.parse_qs(parsed.query)
    sni = query.get("sni", [server_host])[0] or server_host
    insecure = query.get("insecure", query.get("allowInsecure", ["0"]))[0] in {"1", "true", "True"}
    outbound: dict = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": server_host,
        "server_port": server_port,
        "password": password,
        "tls": {"enabled": True, "server_name": sni, "insecure": insecure},
    }
    if query.get("alpn"):
        outbound["tls"]["alpn"] = query["alpn"][0].split(",")
    obfs_type = query.get("obfs", [""])[0]
    if obfs_type:
        outbound["obfs"] = {"type": obfs_type, "password": query.get("obfs-password", [""])[0]}
    return outbound


def generate_hysteria_v1_outbound(parsed: urllib.parse.ParseResult) -> dict:
    """Legacy Hysteria v1 (hysteria://) - different wire format from v2/hy2."""
    server_host = parsed.hostname
    server_port = parsed.port or 443
    if not server_host:
        raise ValueError("invalid Hysteria URI: missing host")
    query = urllib.parse.parse_qs(parsed.query)
    auth = query.get("auth", [urllib.parse.unquote(parsed.username or "")])[0]
    sni = query.get("peer", query.get("sni", [server_host]))[0] or server_host
    outbound: dict = {
        "type": "hysteria",
        "tag": "proxy",
        "server": server_host,
        "server_port": server_port,
        "up_mbps": int(query.get("upmbps", ["100"])[0] or 100),
        "down_mbps": int(query.get("downmbps", ["100"])[0] or 100),
        "tls": {"enabled": True, "server_name": sni},
    }
    if auth:
        outbound["auth_str"] = auth
    if query.get("alpn"):
        outbound["tls"]["alpn"] = query["alpn"][0].split(",")
    if query.get("insecure", ["0"])[0] in {"1", "true", "True"}:
        outbound["tls"]["insecure"] = True
    obfs = query.get("obfs", [""])[0]
    if obfs:
        outbound["obfs"] = obfs
    return outbound


def make_base_config(listen_port: int, outbound: dict) -> dict:
    return {
        "log": {"level": "error"},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": listen_port,
            "sniff": False,
        }],
        "outbounds": [outbound],
    }


def generate_singbox_config(uri: str, listen_port: int) -> dict:
    parsed = urllib.parse.urlparse(uri)
    scheme = parsed.scheme.lower()
    if scheme == "vless":
        outbound = generate_vless_outbound(parsed)
    elif scheme == "trojan":
        outbound = generate_trojan_outbound(parsed)
    elif scheme == "ss":
        outbound = generate_shadowsocks_outbound(parsed)
    elif scheme == "vmess":
        outbound = generate_vmess_outbound(uri)
    elif scheme in {"hysteria2", "hy2"}:
        outbound = generate_hysteria2_outbound(parsed)
    elif scheme == "hysteria":
        outbound = generate_hysteria_v1_outbound(parsed)
    else:
        raise ValueError(f"unsupported protocol: {scheme or 'unknown'}")
    return make_base_config(listen_port, outbound)


def normalize_country_language(language: str) -> str:
    aliases = {"pt-br": "pt-BR", "zh-cn": "zh-CN"}
    normalized = (language or "en").strip()
    return aliases.get(normalized.lower(), normalized or "en")


def lookup_country(reader: object, ip: str, language: str = "en") -> tuple[str, str]:
    geo_data = reader.country(ip)
    language = normalize_country_language(language)
    country_name = geo_data.country.names.get(language) or geo_data.country.names.get("en") or geo_data.country.name or "Unknown"
    country_code = geo_data.country.iso_code or "UN"
    replacements = COUNTRY_REPLACEMENTS.get(language, {})
    return country_code, replacements.get(country_name, country_name)


def get_old_remark(uri: str) -> str:
    if uri.startswith("vmess://") and "@" not in uri.removeprefix("vmess://"):
        try:
            _data, remark = parse_vmess_uri(uri)
            return remark
        except Exception:
            return ""
    return decode_fragment(urllib.parse.urlparse(uri).fragment)


def get_uri_server_endpoint(uri: str) -> tuple[str | None, int | None]:
    """(host, port) straight from the share link, no proxying required."""
    scheme = urllib.parse.urlparse(uri).scheme.lower()
    if scheme == "vmess" and "@" not in uri.removeprefix("vmess://"):
        try:
            data, _remark = parse_vmess_uri(uri)
            host = data.get("add") or data.get("address")
            port = data.get("port")
            return (str(host) if host else None, int(port) if port else None)
        except Exception:
            return None, None
    parsed = urllib.parse.urlparse(uri)
    try:
        port = parsed.port
    except ValueError:
        port = None
    return parsed.hostname, port


def get_uri_server_host(uri: str) -> str | None:
    """Bare server hostname/IP straight from the share link, no proxying required."""
    return get_uri_server_endpoint(uri)[0]


_PLACEHOLDER_HOSTS = {"0.0.0.0", "::", "0000:0000:0000:0000:0000:0000:0000:0000"}


def is_placeholder_endpoint(uri: str) -> bool:
    """
    Catches obviously-dead stub entries some subscriptions leave behind for
    expired plans (e.g. server 0.0.0.0, port 1). There's nothing to resolve
    or geoip here, so these should be dropped entirely rather than showing
    up unrenamed in unstable.
    """
    host, port = get_uri_server_endpoint(uri)
    if not host or host in _PLACEHOLDER_HOSTS:
        return True
    if port is not None and port <= 1:
        return True
    return False


def resolve_host_ip(host: str | None) -> str | None:
    """Return host unchanged if it's already an IP, otherwise resolve it via DNS."""
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def geoip_lookup_ip(geoip_path: Path, ip: str | None, language: str) -> tuple[str, str] | None:
    if not ip:
        return None
    try:
        with geoip2.database.Reader(str(geoip_path)) as reader:
            return lookup_country(reader, ip, language)
    except Exception:
        return None


def resolve_uri_geo(uri: str, geoip_path: Path, remark_language: str) -> tuple[str, str, str]:
    """
    Best-effort geo lookup for a link's server address, used when the live
    connectivity check fails (or the protocol isn't even supported for
    checking). We never routed through the (dead) proxy for this - we just
    take the address straight from the link, resolve it via DNS if it's a
    domain, and geoip that IP directly. This is what lets "unstable" links
    get a proper country remark instead of just "Failed".
    """
    host = get_uri_server_host(uri)
    ip = resolve_host_ip(host)
    geo = geoip_lookup_ip(geoip_path, ip, remark_language)
    if geo:
        country_code, country_name = geo
        return country_code, country_name, ip or ""
    return "UN", "Unknown", ip or ""


def _remark_values(item: CheckResult, index: int, total: int) -> dict:
    return {
        "flag": get_unicode_flag(item.country_code),
        "country": item.country_name,
        "index": str(index),
        "index_suffix": f" {index}" if total > 1 else "",
        "old": item.old_remark,
        "protocol": item.protocol.upper(),
        "latency_ms": str(item.latency_ms),
        "ip": item.real_ip,
    }


def format_results(results: list[CheckResult], remark_format: str, is_working: bool) -> list[str]:
    if is_working:
        sorted_results = sorted(results, key=lambda r: (r.country_name, r.latency_ms))
        output: list[str] = []
        for index, item in enumerate(sorted_results, start=1):
            parsed = urllib.parse.urlparse(item.uri)
            values = _remark_values(item, index, len(sorted_results))
            remark = f"{remark_format.format(**values)} ✅".strip()
            output.append(urllib.parse.urlunparse(parsed._replace(fragment=urllib.parse.quote(remark))))
        return output

    resolved = [r for r in results if r.country_code != "UN"]
    unresolved = [r for r in results if r.country_code == "UN"]
    resolved_sorted = sorted(resolved, key=lambda r: r.country_name)

    output = []
    for index, item in enumerate(resolved_sorted, start=1):
        parsed = urllib.parse.urlparse(item.uri)
        values = _remark_values(item, index, len(resolved_sorted))
        remark = f"{remark_format.format(**values)} ✅".strip()
        output.append(urllib.parse.urlunparse(parsed._replace(fragment=urllib.parse.quote(remark))))

    for item in unresolved:
        parsed = urllib.parse.urlparse(item.uri)
        remark = item.old_remark
        fragment = urllib.parse.quote(remark) if remark else ""
        output.append(urllib.parse.urlunparse(parsed._replace(fragment=fragment)))

    return output


def check_proxy(uri: str, singbox_path: str, geoip_path: Path, timeout: float, temp_dir: Path, progress: Progress, remark_language: str) -> CheckResult:
    scheme = urllib.parse.urlparse(uri).scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        progress.next()
        country_code, country_name, real_ip = resolve_uri_geo(uri, geoip_path, remark_language)
        return CheckResult(uri=uri, country_name=country_name, country_code=country_code, real_ip=real_ip, latency_ms=-1, protocol=scheme, old_remark=get_old_remark(uri), is_working=False)

    config_path: Path | None = None
    process = None
    try:
        socks_port = get_free_port()
        config_path = temp_dir / f"singbox_{socks_port}.json"
        config = generate_singbox_config(uri, socks_port)
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")

        process = subprocess.Popen(
            [singbox_path, "run", "-c", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        time.sleep(0.7)
        if process.poll() is not None:
            raise RuntimeError("sing-box exited before check")

        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}", "https": f"socks5h://127.0.0.1:{socks_port}"}
        start_time = time.perf_counter()
        response = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=timeout)
        latency_ms = int((time.perf_counter() - start_time) * 1000)
        response.raise_for_status()
        real_ip = response.json().get("origin", "").split(",")[0].strip()
        if not real_ip:
            raise RuntimeError("empty exit IP")

        with geoip2.database.Reader(str(geoip_path)) as reader:
            country_code, country_name = lookup_country(reader, real_ip, remark_language)

        step = progress.next()
        print(f"[{step}/{progress.total}] [OK] {real_ip} -> {country_name} ({latency_ms} ms)")
        return CheckResult(uri=uri, country_name=country_name, country_code=country_code, real_ip=real_ip, latency_ms=latency_ms, protocol=scheme, old_remark=get_old_remark(uri), is_working=True)
    except Exception:
        step = progress.next()
        print(f"[{step}/{progress.total}] [FAIL] {uri[:55]}...")
        # proxy check failed, but we can still try to place the server on the
        # map: pull its address straight from the link and geoip that.
        country_code, country_name, real_ip = resolve_uri_geo(uri, geoip_path, remark_language)
        return CheckResult(uri=uri, country_name=country_name, country_code=country_code, real_ip=real_ip, latency_ms=-1, protocol=scheme, old_remark=get_old_remark(uri), is_working=False)
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
        if config_path:
            try:
                config_path.unlink(missing_ok=True)
            except OSError:
                pass


def download_geoip(output: Path, url: str = DEFAULT_GEOIP_URL) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    response = requests.get(url, timeout=60)
    response.raise_for_status()
    output.write_bytes(response.content)


def fetch_all_subscriptions(urls: list[str], hwid: str | None) -> list[str]:
    collected: list[str] = []
    for index, url in enumerate(urls, start=1):
        try:
            body = fetch_subscription(url, hwid)
            links = extract_subscription_links(body)
            collected.extend(links)
            print(f"[{index}/{len(urls)}] fetched {len(links)} links")
        except Exception as exc:
            print(f"[{index}/{len(urls)}] fetch failed: {exc}", file=sys.stderr)
    return dedupe_links(collected, by_endpoint=False)


def update_default(default_path: Path, subs_path: Path, hwid: str | None, singbox_path: str, geoip_path: Path, threads: int, timeout: float, remark_format: str, remark_language: str) -> int:
    headers, _existing_links = split_default_file(default_path)
    subs = [line.strip() for line in subs_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not subs:
        print("Error: no subscription URLs provided", file=sys.stderr)
        return 2

    candidates = fetch_all_subscriptions(subs, hwid)
    candidates = dedupe_links(candidates, by_endpoint=True)

    placeholder_candidates = [uri for uri in candidates if is_placeholder_endpoint(uri)]
    if placeholder_candidates:
        print(f"Skipping {len(placeholder_candidates)} placeholder/dead links (e.g. 0.0.0.0)")
        candidates = [uri for uri in candidates if uri not in placeholder_candidates]

    print(f"Links to check: {len(candidates)}")

    results: list[CheckResult] = []
    progress = Progress(len(candidates))
    unstable_path = default_path.parent / "unstable"

    with tempfile.TemporaryDirectory(prefix="default_updater_") as temp:
        temp_dir = Path(temp)
        with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
            futures = [
                executor.submit(check_proxy, uri, singbox_path, geoip_path, timeout, temp_dir, progress, remark_language)
                for uri in candidates
            ]
            for future in as_completed(futures):
                result = future.result()
                results.append(result)

    working_results = [r for r in results if r.is_working]
    failed_results = [r for r in results if not r.is_working]

    working_links = format_results(working_results, remark_format, is_working=True)
    write_default_file(default_path, headers, working_links)

    unstable_headers, _ = split_default_file(unstable_path) if unstable_path.exists() else ([], [])
    if not unstable_headers:
        unstable_headers = UNSTABLE_HEADER_LINES
    failed_links = format_results(failed_results, remark_format, is_working=False)
    write_default_file(unstable_path, unstable_headers, failed_links)
    print(f"Done: wrote {len(working_links)} working links to {default_path} and {len(failed_links)} failed links to {unstable_path}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fetch private subscriptions, validate links, and refresh the public default file.")
    parser.add_argument("--default", type=Path, default=Path("default"))
    parser.add_argument("--subs", type=Path, required=True)
    parser.add_argument("--hwid")
    parser.add_argument("--sing-box", dest="sing_box", default="./sing-box-bin/sing-box")
    parser.add_argument("--geoip", type=Path, default=Path("GeoLite2-Country.mmdb"))
    parser.add_argument("--threads", type=int, default=24)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--remark-format", default="{flag} {country}{index_suffix}")
    parser.add_argument("--remark-language", default="en")
    parser.add_argument("--download-geoip", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.download_geoip or not args.geoip.exists():
        download_geoip(args.geoip)
    return update_default(args.default, args.subs, args.hwid, args.sing_box, args.geoip, args.threads, args.timeout, args.remark_format, args.remark_language)


if __name__ == "__main__":
    raise SystemExit(main())
