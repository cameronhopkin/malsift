"""Indicator-of-compromise extraction.

Runs on the RAW extracted strings (or raw script text) before any comment stripping,
payload isolation, or content guarding, so sanitizing can never hide an indicator from the
analyst. Indicators are descriptive facts about the sample; reports defang them by default
so they are not clickable.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

MAX_PER_TYPE = 500

_URL = re.compile(r"(?i)\b(?:https?|ftps?|hxxps?|wss?)://[^\s\"'<>`\\^{}|\x00]+")
_IPV4 = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])"
)
_DOMAIN = re.compile(
    r"(?i)(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-]|\.\w)"
)
_WIN_PATH = re.compile(
    r"(?i)(?:\b[a-z]:\\|%[a-z_]+%\\|\\\\[\w.$-]+\\)(?:[^\\/:*?\"<>|\r\n\x00%]+\\)*[^\\/:*?\"<>|\r\n\x00\s]*"
)
_UNIX_PATH = re.compile(
    r"(?<![\w/.:~-])/(?:etc|tmp|var|usr|bin|sbin|home|root|dev|proc|opt|lib|lib64|run|srv|"
    r"Library|Users|System|Applications|private|Volumes)(?:/[\w.@+-]+)+/?"
)

# gTLDs commonly seen in samples. Two-letter ccTLDs are accepted too unless they collide
# with a common file extension (see _NOT_TLD).
_GTLDS = {
    "com", "net", "org", "info", "biz", "io", "xyz", "top", "online", "site", "club", "app",
    "dev", "cloud", "gov", "edu", "mil", "int", "onion", "shop", "store", "tech", "space",
    "website", "live", "link", "work", "click", "icu", "pro", "name", "mobi", "asia", "tel",
    "loan", "win", "bid", "download", "stream", "racing", "review", "party", "trade", "date",
    "host", "fun", "world", "today", "zip", "mov", "lol", "rest", "monster", "buzz", "cyou",
    "life", "digital", "network", "services", "support", "systems", "solutions", "email",
}
_NOT_TLD = {
    # file extensions / code identifiers that look like TLDs
    "py", "sh", "pl", "md", "cs", "ps", "so", "db", "rs", "js", "rb", "go", "hs", "ml", "ts",
    "cc", "hh", "mm", "vb", "fs", "gz", "xz", "bz", "7z", "pm", "lo", "la", "ko", "jar",
    "dll", "exe", "sys", "drv", "ocx", "cpl", "scr", "bat", "cmd", "ps1", "vbs", "txt",
    "log", "ini", "cfg", "dat", "tmp", "bin", "json", "xml", "html", "htm", "pdb", "lib",
    "obj", "png", "jpg", "gif", "ico", "manifest", "config", "resources", "pyc", "class",
}


@dataclass
class IOCSet:
    urls: list[str] = field(default_factory=list)
    ips: list[dict[str, Any]] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {k: len(getattr(self, k)) for k in ("urls", "ips", "domains", "paths")}

    def to_dict(self, defang: bool = True) -> dict[str, Any]:
        f = defang_value if defang else (lambda v, _kind: v)
        return {
            "defanged": defang,
            "counts": self.counts(),
            "urls": [f(u, "url") for u in self.urls],
            "ips": [{**ip, "value": f(ip["value"], "ip")} for ip in self.ips],
            "domains": [f(d, "domain") for d in self.domains],
            "paths": list(self.paths),
        }


def _add(seq: list, value: Any, seen: set) -> None:
    key = value["value"] if isinstance(value, dict) else value
    if key in seen or len(seq) >= MAX_PER_TYPE:
        return
    seen.add(key)
    seq.append(value)


def _clean_url(u: str) -> str:
    return u.rstrip(".,;:!?)]}'\"")


def _url_host(u: str) -> str | None:
    m = re.match(r"(?i)^[a-z]+://(?:[^@/]*@)?(\[[^\]]+\]|[^:/?#]+)", u)
    return m.group(1).lower() if m else None


def _is_domain(candidate: str, tld: str) -> bool:
    tld = tld.lower()
    if tld in _NOT_TLD:
        return False
    if tld in _GTLDS:
        return True
    return len(tld) == 2


def extract(items: Iterable[str]) -> IOCSet:
    res = IOCSet()
    seen: dict[str, set] = {"u": set(), "i": set(), "d": set(), "p": set()}

    def add_ip(value: str) -> None:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return
        if ip.is_unspecified:
            return
        scope = (
            "loopback" if ip.is_loopback
            else "private" if ip.is_private
            else "reserved" if (ip.is_reserved or ip.is_multicast or ip.is_link_local)
            else "public"
        )
        _add(res.ips, {"value": value, "scope": scope}, seen["i"])

    for raw in items:
        if not raw:
            continue
        url_spans: list[tuple[int, int]] = []
        for m in _URL.finditer(raw):
            url = _clean_url(m.group())
            url_spans.append((m.start(), m.start() + len(url)))
            _add(res.urls, url, seen["u"])
            host = _url_host(url)
            if host:
                if _IPV4.fullmatch(host):
                    add_ip(host)
                elif "." in host:
                    _add(res.domains, host, seen["d"])

        for m in _IPV4.finditer(raw):
            add_ip(m.group())

        for m in _DOMAIN.finditer(raw):
            if any(s <= m.start() < e for s, e in url_spans):
                continue
            if _is_domain(m.group(1), m.group(2)):
                _add(res.domains, m.group(1).lower(), seen["d"])

        for rx in (_WIN_PATH, _UNIX_PATH):
            for m in rx.finditer(raw):
                if any(s <= m.start() < e for s, e in url_spans):
                    continue
                path = m.group().rstrip(".,;:)'\"")
                if len(path) > 3:
                    _add(res.paths, path, seen["p"])
    return res


def defang_value(value: str, kind: str) -> str:
    """Defang an indicator so it is not clickable/resolvable when a report is shared."""
    if kind == "url":
        m = re.match(r"(?i)^([a-z]+)://([^/?#]*)(.*)$", value)
        if not m:
            return value
        scheme, host, rest = m.groups()
        scheme = re.sub(r"(?i)^http", "hxxp", scheme)
        scheme = re.sub(r"(?i)^ftp", "fxp", scheme)
        return f"{scheme}[://]{host.replace('.', '[.]')}{rest}"
    if kind in ("ip", "domain"):
        return value.replace(".", "[.]")
    return value
