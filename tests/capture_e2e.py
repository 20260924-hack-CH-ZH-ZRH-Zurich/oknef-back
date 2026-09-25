"""Exercise multipart capture receipts against running backend/database services.

Fixtures are synthetic. A receipt verifies bytes received, not document authenticity,
OCR correctness, camera origin, liveness, or fraud-detector accuracy.
"""
import argparse
import base64
import hashlib
import http.cookiejar
import json
import secrets
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--base", required=True)
parser.add_argument("--origin", required=True)
args = parser.parse_args()
checks = []
PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aY4sAAAAASUVORK5CYII=")


def check(name, condition):
    checks.append({"test": name, "passed": bool(condition)})
    if not condition:
        raise AssertionError(name)


class Client:
    def __init__(self):
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, method="GET", data=None, content_type="application/json"):
        request = urllib.request.Request(args.base + path, method=method, data=data,
            headers={"Origin": args.origin, "Content-Type": content_type})
        try:
            with self.opener.open(request, timeout=30) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            try:
                payload = json.load(error)
            except (ValueError, UnicodeError):
                payload = {"error": "non-JSON error"}
            return error.code, payload

    def call(self, path, method="GET", body=None):
        return self.request(path, method, json.dumps(body).encode() if body is not None else None)

    def capture(self, fields, files=(("capture.png", "image/png", PNG),)):
        boundary = "oknef-" + secrets.token_hex(16)
        parts = []
        for name, value in fields:
            parts.extend([f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n".encode(),
                value.encode(), b"\r\n"])
        for name, mime, contents in files:
            parts.extend([f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\nContent-Type: {mime}\r\n\r\n".encode(), contents, b"\r\n"])
        parts.append(f"--{boundary}--\r\n".encode())
        return self.request("/api/security/sessions/capture", "POST", b"".join(parts),
            "multipart/form-data; boundary=" + boundary)


def registered(name):
    client = Client()
    status, user = client.call("/api/auth/register", "POST", {
        "name": name, "email": secrets.token_hex(10) + "@example.test",
        "password": secrets.token_urlsafe(24), "account_type": "personal"})
    check(name + " registered", status == 200)
    return client, user["user"]


owner, _ = registered("Capture owner")
stranger, _ = registered("Capture stranger")
fields = [("kind", "document"), ("title", "Synthetic receipt test"),
    ("content", "User reviewed test extraction"), ("locale", "en"), ("source", "camera")]
check("capture requires authentication", Client().capture(fields)[0] == 401)
status, session = owner.capture(fields)
check("capture creates durable session", status == 200 and bool(session["id"]))
evidence = session["evidence"][0]
check("server computes exact byte digest", evidence["sha256"] == hashlib.sha256(PNG).hexdigest())
check("server computes exact byte length", evidence["size_bytes"] == len(PNG))
check("receipt has honest provenance", evidence["provenance"] == "server_received_upload"
    and evidence["digest_verified"] and not evidence["source_verified"])
check("plaintext extraction provenance is explicit", evidence["content_provenance"] == "user_reviewed_extraction")
check("media bytes are not retained", not evidence["bytes_retained"] and "data_url" not in evidence)
check("receipt never authenticates document", session["assessment"]["authenticity_verified"] is False)
path = "/api/security/sessions/" + session["id"]
check("receipt survives reopening session", owner.call(path)[1]["evidence"] == session["evidence"])
check("foreign tenant cannot read receipt", stranger.call(path)[0] == 404)
events = owner.call("/api/security/overview")[1]["events"]
check("capture persists corresponding audit event", any(event["session_id"] == session["id"] for event in events))
status, chat = owner.call("/api/chat/sessions", "POST", {"title": "Capture context"})
check("parent chat prepared", status == 200)
status, linked = owner.capture(fields + [("parent_session_id", chat["id"])])
check("capture links owned parent session", status == 200 and linked["parent_session_id"] == chat["id"])
check("foreign parent session rejected", stranger.capture(fields + [("parent_session_id", chat["id"])])[0] == 400)
for key in ["digest_verified", "sha256", "tenant_id", "assessment", "evidence", "source_verified"]:
    check("rejects forged " + key, owner.capture(fields + [(key, "forged")])[0] == 400)
check("duplicate text field rejected", owner.capture(fields + [("kind", "identity")])[0] == 400)
check("duplicate file rejected", owner.capture(fields, files=(("a.png", "image/png", PNG), ("b.png", "image/png", PNG)))[0] == 400)
check("missing file rejected", owner.capture(fields, files=())[0] == 400)
check("signature mismatch rejected", owner.capture(fields, files=(("bad.png", "image/png", b"not an image"),))[0] == 400)
check("path filename rejected", owner.capture(fields, files=(("../bad.png", "image/png", PNG),))[0] == 400)
check("future capture time rejected", owner.capture(fields + [("captured_at", "18446744073709551615")])[0] == 400)
check("invalid asset array rejected", owner.capture(fields + [("asset_ids", "not json")])[0] == 400)
check("unsupported locale rejected", owner.capture([(key, "xx" if key == "locale" else value) for key, value in fields])[0] == 400)
print(json.dumps({"passed": len(checks), "failed": 0, "checks": checks,
    "scope": "Real HTTP/database capture persistence with synthetic bytes; no authenticity claim"}, indent=2))
