"""Signed, expiring download URLs for media in the bridge store.

download_media returns a path on the server's disk, which a client on another
machine cannot open. When WHATSAPP_MEDIA_BASE_URL is set, download_media also
returns a URL served by this server's own HTTP transport. The URL carries an
HMAC over the store-relative path and an expiry, so it grants access to that
one file only, and only until it expires or the server restarts.
"""

import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path
from urllib.parse import quote, urlencode

ROUTE_PREFIX = "/media/"
URL_TTL_SECONDS = 3600

# Per process: a restart invalidates every URL handed out before it.
_SECRET = secrets.token_bytes(32)


def base_url() -> str | None:
    """Public URL under which clients reach this server, or None if unset."""
    return os.getenv("WHATSAPP_MEDIA_BASE_URL", "").strip().rstrip("/") or None


def _signature(rel_path: str, expires: int) -> str:
    return hmac.new(_SECRET, f"{rel_path}\n{expires}".encode(), hashlib.sha256).hexdigest()


def _relative(file_path: str, store_root: Path) -> str | None:
    try:
        return Path(file_path).resolve().relative_to(store_root.resolve()).as_posix()
    except ValueError:
        return None


def signed_url(file_path: str, store_root: Path, now: float | None = None) -> str | None:
    """Return a download URL for a file inside the store, or None.

    None when WHATSAPP_MEDIA_BASE_URL is unset or the file is outside the store.
    """
    base = base_url()
    rel = _relative(file_path, store_root)
    if base is None or rel is None:
        return None
    expires = int(now if now is not None else time.time()) + URL_TTL_SECONDS
    query = urlencode({"expires": expires, "sig": _signature(rel, expires)})
    return f"{base}{ROUTE_PREFIX}{quote(rel)}?{query}"


def resolve(rel_path: str, expires: str, sig: str, store_root: Path, now: float | None = None) -> Path | None:
    """Return the file a signed URL names, or None if it is invalid, expired or gone."""
    try:
        expires_at = int(expires)
    except ValueError:
        return None
    if expires_at < (now if now is not None else time.time()):
        return None
    if not hmac.compare_digest(sig, _signature(rel_path, expires_at)):
        return None
    root = store_root.resolve()
    target = (root / rel_path).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return None
    return target


# Uploads: the mirror of download links, for send_file from a remote client.
# The bridge only sends files under its media roots, so uploads land in the
# first of those (the same default outbox the bridge creates).
UPLOAD_ROUTE_PREFIX = "/upload/"
MAX_UPLOAD_BYTES = 2 * 1024**3  # WhatsApp's document limit
_DEFAULT_OUTBOX = ".local/share/whatsapp-mcp/outbox"


def upload_root() -> Path:
    """Directory under the bridge's first media root that receives uploads."""
    roots = [r.strip() for r in os.getenv("WHATSAPP_MEDIA_ROOTS", "").split(os.pathsep) if r.strip()]
    root = Path(roots[0]) if roots else Path.home() / _DEFAULT_OUTBOX
    return root / "uploads"


def _safe_name(filename: str) -> str | None:
    name = Path(filename.replace("\\", "/")).name.strip()
    return None if name in ("", ".", "..") else name


def sweep_expired_uploads(root: Path, now: float | None = None) -> None:
    """Delete upload directories whose links expired more than a TTL ago."""
    cutoff = (now if now is not None else time.time()) - 2 * URL_TTL_SECONDS
    if not root.is_dir():
        return
    for slot in root.iterdir():
        if slot.is_dir() and slot.stat().st_mtime < cutoff:
            for f in slot.iterdir():
                f.unlink(missing_ok=True)
            slot.rmdir()


def signed_upload(filename: str, now: float | None = None) -> dict[str, str] | None:
    """Return {url, media_path} for a one-file upload, or None.

    None when WHATSAPP_MEDIA_BASE_URL is unset or the filename is empty.
    """
    base = base_url()
    name = _safe_name(filename)
    if base is None or name is None:
        return None
    root = upload_root()
    sweep_expired_uploads(root, now)
    rel = f"{secrets.token_hex(16)}/{name}"
    expires = int(now if now is not None else time.time()) + URL_TTL_SECONDS
    query = urlencode({"expires": expires, "sig": _signature("upload:" + rel, expires)})
    return {
        "url": f"{base}{UPLOAD_ROUTE_PREFIX}{quote(rel)}?{query}",
        "media_path": str(root / rel),
    }


def upload_target(rel_path: str, expires: str, sig: str, now: float | None = None) -> Path | None:
    """Return where a signed upload URL writes, or None if invalid, expired or already used."""
    try:
        expires_at = int(expires)
    except ValueError:
        return None
    if expires_at < (now if now is not None else time.time()):
        return None
    if not hmac.compare_digest(sig, _signature("upload:" + rel_path, expires_at)):
        return None
    root = upload_root().resolve()
    target = (root / rel_path).resolve()
    if not target.is_relative_to(root) or target.exists():
        return None
    return target
