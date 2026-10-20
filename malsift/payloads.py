"""Payload isolation for scripts.

Droppers and loaders embed encoded payloads (base64 runs, hex strings, ``\\xNN`` escapes,
``0x..`` byte arrays) inside otherwise short script logic. Those blobs are useless to a
language model, can be enormous, and are a convenient place to hide injection text. This
module separates them from the script logic:

* each blob is replaced in the model's view by a marker such as
  ``[payload blob #1 kind=base64 len=4096 sha256=ab12...]``
* the report records kind, offset, length, the SHA-256 of the blob text and, when it
  decodes cleanly, the SHA-256/size/leading-magic of the decoded bytes

Raw blob content is never sent to the model and never written to the report. Nothing is
executed or written to disk.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import re
from dataclasses import asdict, dataclass

_MAGICS = (
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"%PDF", "pdf"),
    (b"\xd0\xcf\x11\xe0", "ole"),
    (b"7z\xbc\xaf", "7z"),
    (b"Rar!", "rar"),
    (b"\xca\xfe\xba\xbe", "macho-fat"),
    (b"\xcf\xfa\xed\xfe", "macho"),
)


@dataclass
class PayloadBlob:
    index: int
    kind: str
    offset: int
    length: int
    sha256: str
    decoded_size: int | None = None
    decoded_sha256: str | None = None
    decoded_magic: str | None = None
    decoded_entropy: float | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return max(0.0, -sum((c / n) * math.log2(c / n) for c in counts if c))


def _decode(kind: str, blob: str) -> bytes | None:
    try:
        if kind == "base64":
            s = re.sub(r"\s+", "", blob)
            return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
        if kind == "hex":
            return binascii.unhexlify(blob)
        if kind == "hex_escape":
            return bytes(int(h, 16) for h in re.findall(r"\\x([0-9A-Fa-f]{2})", blob))
        if kind == "byte_array":
            return bytes(int(h, 16) for h in re.findall(r"0x([0-9A-Fa-f]{2})", blob))
    except (ValueError, binascii.Error):
        return None
    return None


def _pattern(min_b64: int, min_hex: int) -> re.Pattern[str]:
    pairs = max(min_hex // 2, 8)
    return re.compile(
        r"(?P<hex_escape>(?:\\x[0-9A-Fa-f]{2}){" + str(pairs) + r",})"
        + r"|(?P<byte_array>(?:0x[0-9A-Fa-f]{2}\s*,\s*){" + str(pairs - 1) + r",}0x[0-9A-Fa-f]{2})"
        + r"|(?P<hex>(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}){" + str(pairs) + r",}(?![0-9A-Za-z]))"
        + r"|(?P<base64>(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{" + str(min_b64) + r",}={0,2}(?![A-Za-z0-9+/=]))"
    )


def _plausible_base64(s: str) -> bool:
    body = s.rstrip("=")
    return (
        any(c.islower() for c in body)
        and any(c.isupper() for c in body)
        and any(c.isdigit() or c in "+/" for c in body)
    )


def isolate(text: str, min_base64_len: int = 80, min_hex_len: int = 64) -> tuple[str, list[PayloadBlob]]:
    """Replace embedded payload blobs with hash markers. Returns (text, blobs).

    Offsets in the returned records refer to the input ``text``.
    """
    blobs: list[PayloadBlob] = []

    def repl(m: re.Match[str]) -> str:
        kind = m.lastgroup or "unknown"
        blob = m.group()
        if kind == "base64" and not _plausible_base64(blob):
            return blob
        if kind == "hex" and not any(c.isdigit() for c in blob):
            return blob  # e.g. "aaaa..." or "deadbeef..." words, not an encoded payload
        raw_sha = hashlib.sha256(blob.encode("utf-8", "ignore")).hexdigest()
        rec = PayloadBlob(
            index=len(blobs) + 1, kind=kind, offset=m.start(), length=len(blob), sha256=raw_sha
        )
        decoded = _decode(kind, blob)
        if decoded:
            rec.decoded_size = len(decoded)
            rec.decoded_sha256 = hashlib.sha256(decoded).hexdigest()
            rec.decoded_entropy = round(_entropy(decoded), 3)
            rec.decoded_magic = next((n for sig, n in _MAGICS if decoded.startswith(sig)), None)
        blobs.append(rec)
        return f"[payload blob #{rec.index} kind={kind} len={len(blob)} sha256={raw_sha[:16]}]"

    return _pattern(min_base64_len, min_hex_len).sub(repl, text), blobs
