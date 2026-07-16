import argparse
import base64
import html
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


@dataclass(frozen=True)
class CheckResult:
    uri: str
    country_name: str
    country_code: str
    real_ip: str
    latency_ms: int
    protocol: str
    old_remark: str


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
    if tls.get("serverName"):
        params["sni"] = str(tls["serverName"])
    elif reality.get("serverName"):
        params["sni"] = str(reality["serverName"])
    if tls.get("fingerprint"):
        params["fp"] = str(tls["fingerprint"])
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


def build_stream_settings(query: dict[str, list[str]], server_host: str) -> dict:
    transport = query.get("type", ["tcp"])[0] or "tcp"
    transport = normalize_transport(transport)
    security = query.get("security", ["none"])[0] or "none"
    sni = query.get("sni", [server_host])[0] or server_host
    fingerprint = query.get("fp", ["chrome"])[0] or "chrome"

    stream = {"network": transport, "security": security}
    if security == "tls":
        stream["tlsSettings"] = {"serverName": sni, "fingerprint": fingerprint}
        if query.get("allowInsecure"):
            stream["tlsSettings"]["allowInsecure"] = query["allowInsecure"][0] in {"1", "true", "True"}
        if query.get("alpn"):
            stream["tlsSettings"]["alpn"] = query["alpn"][0].split(",")
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fingerprint,
            "publicKey": query.get("pbk", [""])[0],
            "shortId": query.get("sid", [""])[0],
            "spiderX": query.get("spx", [""])[0],
        }

    if transport == "ws":
        stream["wsSettings"] = {
            "path": query.get("path", ["/"])[0] or "/",
            "headers": {"Host": query.get("host", [server_host])[0] or server_host},
        }
    elif transport == "grpc":
        stream["grpcSettings"] = {
            "serviceName": query.get("serviceName", [""])[0],
            "multiMode": query.get("mode", [""])[0] == "multi",
        }
    elif transport == "xhttp":
        stream["xhttpSettings"] = {
            "path": query.get("path", ["/"])[0] or "/",
            "host": query.get("host", [server_host])[0] or server_host,
            "mode": query.get("mode", ["auto"])[0] or "auto",
        }
    elif transport == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": query.get("path", ["/"])[0] or "/",
            "host": query.get("host", [server_host])[0] or server_host,
        }
    elif transport == "hysteria":
        stream["hysteriaSettings"] = {
            "version": 2,
            "auth": query.get("auth", [""])[0],
            "udpIdleTimeout": int(query.get("udpIdleTimeout", ["60"])[0] or 60),
        }
    elif transport == "tcp" and query.get("headerType", ["none"])[0] == "http":
        host = query.get("host", [server_host])[0] or server_host
        path = query.get("path", ["/"])[0] or "/"
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {"path": [path], "headers": {"Host": [host]}},
            }
        }
    return stream


def generate_vless_outbound(parsed: urllib.parse.ParseResult) -> dict:
    user_id = urllib.parse.unquote(parsed.username or "")
    server_host = parsed.hostname
    server_port = parsed.port or 443
    if not user_id or not server_host:
        raise ValueError("invalid VLESS URI: missing user id or host")
    query = urllib.parse.parse_qs(parsed.query)
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": server_host,
                "port": server_port,
                "users": [{
                    "id": user_id,
                    "encryption": query.get("encryption", ["none"])[0] or "none",
                    "flow": query.get("flow", [""])[0],
                }],
            }]
        },
        "streamSettings": build_stream_settings(query, server_host),
    }


def generate_trojan_outbound(parsed: urllib.parse.ParseResult) -> dict:
    password = urllib.parse.unquote(parsed.username or "")
    server_host = parsed.hostname
    server_port = parsed.port or 443
    if not password or not server_host:
        raise ValueError("invalid Trojan URI: missing password or host")
    query = urllib.parse.parse_qs(parsed.query)
    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": server_host, "port": server_port, "password": password}]},
        "streamSettings": build_stream_settings(query, server_host),
    }


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
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": server_host, "port": server_port, "method": method, "password": password}]},
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
        "headerType": [data.get("headerType") or ""],
        "serviceName": [data.get("serviceName") or ""],
        "mode": [data.get("mode") or ""],
    }
    return {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": server_host, "port": server_port, "users": [{"id": user_id, "alterId": int(data.get("aid") or 0), "security": data.get("scy") or data.get("security") or "auto"}]}]},
        "streamSettings": build_stream_settings(query, server_host),
    }


def generate_hysteria_outbound(parsed: urllib.parse.ParseResult) -> dict:
    password = urllib.parse.unquote(parsed.username or "")
    server_host = parsed.hostname
    server_port = parsed.port or 443
    if not password or not server_host:
        raise ValueError("invalid Hysteria URI: missing password or host")
    query = urllib.parse.parse_qs(parsed.query)
    stream_query = {
        "type": ["hysteria"],
        "security": [query.get("security", ["tls"])[0] or "tls"],
        "sni": [query.get("sni", [server_host])[0] or server_host],
        "auth": [password],
        "udpIdleTimeout": [query.get("udpIdleTimeout", ["60"])[0]],
        "allowInsecure": [query.get("insecure", query.get("allowInsecure", [""]))[0]],
        "alpn": [query.get("alpn", ["h3"])[0] or "h3"],
    }
    return {
        "protocol": "hysteria",
        "settings": {"version": 2, "address": server_host, "port": server_port},
        "streamSettings": build_stream_settings(stream_query, server_host),
    }


def make_base_config(listen_port: int, outbound: dict) -> dict:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": listen_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [outbound],
    }


def generate_xray_config(uri: str, listen_port: int) -> dict:
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
    elif scheme in {"hysteria", "hysteria2", "hy2"}:
        outbound = generate_hysteria_outbound(parsed)
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


def format_remark(template: str, item: CheckResult, index: int, total: int) -> str:
    values = {
        "flag": get_unicode_flag(item.country_code),
        "country": item.country_name,
        "index": str(index),
        "index_suffix": f" {index}" if total > 1 else "",
        "old": item.old_remark,
        "protocol": item.protocol.upper(),
        "latency_ms": str(item.latency_ms),
        "ip": item.real_ip,
    }
    return template.format(**values)


def format_results(results: list[CheckResult], remark_format: str) -> list[str]:
    groups: dict[str, list[CheckResult]] = defaultdict(list)
    for result in results:
        groups[result.country_name].append(result)
    output: list[str] = []
    for country_name in sorted(groups):
        items = sorted(groups[country_name], key=lambda item: item.latency_ms)
        for index, item in enumerate(items, start=1):
            parsed = urllib.parse.urlparse(item.uri)
            remark = format_remark(remark_format, item, index, len(items))
            output.append(urllib.parse.urlunparse(parsed._replace(fragment=urllib.parse.quote(remark))))
    return output


def check_proxy(uri: str, xray_path: str, geoip_path: Path, timeout: float, temp_dir: Path, progress: Progress, remark_language: str) -> CheckResult | None:
    scheme = urllib.parse.urlparse(uri).scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        progress.next()
        return None

    config_path: Path | None = None
    process = None
    try:
        socks_port = get_free_port()
        config_path = temp_dir / f"xray_{socks_port}.json"
        config = generate_xray_config(uri, socks_port)
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")

        process = subprocess.Popen(
            [xray_path, "run", "-c", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        time.sleep(0.7)
        if process.poll() is not None:
            raise RuntimeError("xray exited before check")

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
        return CheckResult(uri=uri, country_name=country_name, country_code=country_code, real_ip=real_ip, latency_ms=latency_ms, protocol=scheme, old_remark=get_old_remark(uri))
    except Exception:
        step = progress.next()
        print(f"[{step}/{progress.total}] [FAIL] {uri[:55]}...")
        return None
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


def update_default(default_path: Path, subs_path: Path, hwid: str | None, xray_path: str, geoip_path: Path, threads: int, timeout: float, remark_format: str, remark_language: str) -> int:
    headers, _existing_links = split_default_file(default_path)
    subs = [line.strip() for line in subs_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not subs:
        print("Error: no subscription URLs provided", file=sys.stderr)
        return 2

    candidates = fetch_all_subscriptions(subs, hwid)
    candidates = dedupe_links(candidates, by_endpoint=True)
    print(f"Links to check: {len(candidates)}")

    results: list[CheckResult] = []
    progress = Progress(len(candidates))
    with tempfile.TemporaryDirectory(prefix="default_updater_") as temp:
        temp_dir = Path(temp)
        with ThreadPoolExecutor(max_workers=max(1, threads)) as executor:
            futures = [
                executor.submit(check_proxy, uri, xray_path, geoip_path, timeout, temp_dir, progress, remark_language)
                for uri in candidates
            ]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)

    renamed = format_results(results, remark_format)
    write_default_file(default_path, headers, renamed)
    print(f"Done: wrote {len(renamed)} working links to {default_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fetch private subscriptions, validate links, and refresh the public default file.")
    parser.add_argument("--default", type=Path, default=Path("default"))
    parser.add_argument("--subs", type=Path, required=True)
    parser.add_argument("--hwid")
    parser.add_argument("--xray", default="./xray-bin/xray")
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
    return update_default(args.default, args.subs, args.hwid, args.xray, args.geoip, args.threads, args.timeout, args.remark_format, args.remark_language)


if __name__ == "__main__":
    raise SystemExit(main())
