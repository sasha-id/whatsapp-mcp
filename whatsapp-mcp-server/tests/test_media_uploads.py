"""Signed media upload URLs: prepare_upload and the streaming PUT route."""

import os
import time
from urllib.parse import urlsplit

import pytest
from starlette.testclient import TestClient

import main
import media_links

BASE = "https://wa.example/acct"


@pytest.fixture
def outbox(tmp_path, monkeypatch):
    root = tmp_path / "outbox"
    monkeypatch.setenv("WHATSAPP_MEDIA_ROOTS", f"{root}{os.pathsep}{tmp_path / 'other'}")
    monkeypatch.setenv("WHATSAPP_MEDIA_BASE_URL", BASE)
    return root


@pytest.fixture
def client():
    return TestClient(main.mcp.streamable_http_app())


def _local(url):
    parts = urlsplit(url)
    return parts.path.removeprefix("/acct") + "?" + parts.query


def test_upload_then_send_path(outbox, client):
    result = main.prepare_upload("../../etc/report 1.pdf")
    assert result["success"]
    media_path = result["media_path"]
    assert media_path.startswith(str(outbox / "uploads"))
    assert media_path.endswith("/report 1.pdf")

    response = client.put(_local(result["url"]), content=iter([b"%PDF-", b"bytes"]))

    assert response.status_code == 201
    assert response.json() == {"media_path": os.path.realpath(media_path), "size": 10}
    with open(media_path, "rb") as f:
        assert f.read() == b"%PDF-bytes"
    assert not os.path.exists(media_path + ".part")


def test_url_accepts_one_upload(outbox, client):
    url = _local(main.prepare_upload("a.txt")["url"])
    assert client.put(url, content=b"one").status_code == 201
    assert client.put(url, content=b"two").status_code == 404


def test_tampered_expired_and_escaping_urls_refused(outbox, client):
    result = main.prepare_upload("a.txt")
    parts = urlsplit(result["url"])
    path = parts.path.removeprefix("/acct")
    assert client.put(path + "?" + parts.query.replace("sig=", "sig=0"), content=b"x").status_code == 404
    assert client.put(path.replace("a.txt", "b.txt") + "?" + parts.query, content=b"x").status_code == 404

    expires = int(time.time()) - 1
    rel = path.removeprefix("/upload/")
    sig = media_links._signature("upload:" + rel, expires)
    assert client.put(f"{path}?expires={expires}&sig={sig}", content=b"x").status_code == 404

    escaping = "../escape.txt"
    future = int(time.time()) + 60
    assert (
        media_links.upload_target(escaping, str(future), media_links._signature("upload:" + escaping, future)) is None
    )
    # A download signature never authorises an upload.
    assert media_links.upload_target(rel, str(future), media_links._signature(rel, future)) is None


def test_oversize_upload_refused(outbox, client, monkeypatch):
    monkeypatch.setattr(media_links, "MAX_UPLOAD_BYTES", 4)
    result = main.prepare_upload("big.bin")
    assert client.put(_local(result["url"]), content=b"12345").status_code == 413
    assert not os.path.exists(result["media_path"])
    assert not os.path.exists(result["media_path"] + ".part")


def test_no_upload_without_base_or_name(outbox, monkeypatch):
    assert not main.prepare_upload("..")["success"]
    monkeypatch.delenv("WHATSAPP_MEDIA_BASE_URL")
    assert not main.prepare_upload("a.txt")["success"]


def test_default_root_is_bridge_outbox(monkeypatch, tmp_path):
    monkeypatch.delenv("WHATSAPP_MEDIA_ROOTS", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert media_links.upload_root() == tmp_path / ".local/share/whatsapp-mcp/outbox/uploads"


def test_sweep_removes_only_stale_slots(outbox):
    root = outbox / "uploads"
    for slot, age in (("old", 3 * media_links.URL_TTL_SECONDS), ("new", 0)):
        (root / slot).mkdir(parents=True)
        (root / slot / "f").write_bytes(b"x")
        stamp = time.time() - age
        os.utime(root / slot, (stamp, stamp))
    media_links.sweep_expired_uploads(root)
    assert sorted(p.name for p in root.iterdir()) == ["new"]
