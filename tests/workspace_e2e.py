"""Exercise workspace persistence and isolation; optional calls use the real configured AI.

No submitted test data represents a real identity, holding or fraud detection benchmark.
"""
import argparse
import base64
import hashlib
import http.cookiejar
import json
import secrets
import struct
import urllib.error
import urllib.request
import zlib

parser = argparse.ArgumentParser()
parser.add_argument("--base", required=True)
parser.add_argument("--origin", required=True)
parser.add_argument("--live-ai", action="store_true")
args = parser.parse_args()
checks = []


class Client:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, path, method="GET", body=None):
        request = urllib.request.Request(args.base + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Origin": args.origin, "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=180) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                return error.code, json.loads(raw)
            except (ValueError, UnicodeError):
                return error.code, {"error": "non-JSON response"}


def check(name, condition):
    checks.append({"test": name, "passed": bool(condition)})
    if not condition:
        raise AssertionError(name)


owner, other = Client(), Client()
for client, mode in [(owner, "company"), (other, "admin")]:
    status, result = client.call("/api/auth/demo", "POST", {"mode": mode})
    check(mode + " demo is isolated and explicitly synthetic", status == 200 and result["user"]["demo_profile"] == mode and result["user"]["demo"] and result["user"]["role"] == "owner")
check("unknown demo privilege rejected", Client().call("/api/auth/demo", "POST", {"mode": "superuser"})[0] == 400)
check("new endpoints require authentication", all(Client().call(path)[0] == 401 for path in ["/api/drive", "/api/integrations", "/api/graph", "/api/chat/sessions", "/api/voice/policy"]))
asset = owner.call("/api/assets")[1]["assets"][0]
foreign_asset = other.call("/api/assets")[1]["assets"][0]
registration = {"name": "Mail inventory", "provider": "mail", "account_label": "Synthetic mailbox", "asset_ids": [asset["id"]]}
status, integration = owner.call("/api/integrations", "POST", registration)
check("integration records do not claim OAuth access", status == 200 and integration["status"] == "registered" and integration["connection_verified"] is False and integration["background_sync"] is False)
check("foreign asset cannot be linked", owner.call("/api/integrations", "POST", dict(registration, asset_ids=[foreign_asset["id"]]))[0] == 400)
check("integration credentials rejected", owner.call("/api/integrations", "POST", dict(registration, access_token="forged"))[0] == 400)
check("admin demo has no cross-tenant privileges", other.call("/api/integrations")[1]["integrations"] == [] and other.call("/api/integrations/" + integration["id"], "DELETE")[0] == 404)
status, chat = owner.call("/api/chat/sessions", "POST", {"title": "Review conversation"})
check("chat session is durable", status == 200 and any(item["id"] == chat["id"] for item in owner.call("/api/chat/sessions")[1]["sessions"]))
check("foreign chat inaccessible", other.call("/api/chat/sessions/" + chat["id"])[0] == 404)
status, voice_chat = owner.call("/api/chat/sessions", "POST", {"title": "Voice transcript evidence"})
transcript_path = "/api/chat/sessions/" + voice_chat["id"] + "/messages"
transcript = {"role": "user", "content": "Synthetic voice transcript", "source": "realtime_transcript"}
check("voice transcript attribution stays client reported", owner.call(transcript_path, "POST", transcript)[1]["provider_attested"] is False)
check("voice transcript cannot cross tenants", other.call(transcript_path, "POST", transcript)[0] == 404)
check("voice transcript cannot forge system role", owner.call(transcript_path, "POST", dict(transcript, role="system"))[0] == 400)
metadata = {"name": "sample.mp4", "mime_type": "video/mp4", "size_bytes": 8,
    "sha256": hashlib.sha256(b"metadata").hexdigest(), "source": "upload"}
submission = {"kind": "video", "title": "Synthetic frame evidence", "content": "Sampled frames require independent authenticity review.", "evidence": [metadata], "asset_ids": [asset["id"]], "parent_session_id": chat["id"]}
status, session = owner.call("/api/security/sessions", "POST", submission)
check("media session stores bounded provenance", status == 200 and session["evidence"][0]["digest_verified"] is False and session["evidence"][0]["bytes_retained"] is False)
check("media session does not invent deepfake result", session["assessment"]["status"] == "inconclusive" and session["assessment"]["authenticity_verified"] is False)
check("foreign parent rejected", other.call("/api/security/sessions", "POST", dict(submission, asset_ids=[]))[0] == 400)
check("evidence inline bytes cannot bypass encrypted drive", owner.call("/api/security/sessions", "POST", dict(submission, evidence=[dict(metadata, data_url="forged")]))[0] == 400)
envelope = {"version": 1, "algorithm": "AES-256-GCM", "iv": base64.b64encode(secrets.token_bytes(12)).decode(), "ciphertext": base64.b64encode(secrets.token_bytes(100000)).decode()}
status, file = owner.call("/api/drive", "POST", {"envelope": envelope})
check("drive stores ciphertext above vault note limit", status == 200 and file["envelope"] == envelope)
check("drive and password vault use separate records", owner.call("/api/vault")[1]["items"] == [])
check("drive ciphertext isolated", other.call("/api/drive")[1]["items"] == [] and other.call("/api/drive/" + file["id"], "DELETE")[0] == 404)
graph = owner.call("/api/graph")[1]
check("graph links actual stored session and asset", any(edge["source"] == session["id"] and edge["target"] == asset["id"] for edge in graph["edges"]))
check("graph contains encrypted drive item", any(node["id"] == file["id"] and node["kind"] == "encrypted_file" for node in graph["nodes"]))
check("graph cannot claim physical network scanning", graph["physical_network_scan"] is False)
status, policy = owner.call("/api/voice/policy", "PUT", {"mode": "trusted_only"})
check("trusted-only policy fails closed", status == 200 and policy["session_allowed"] is False and owner.call("/api/voice/session", "POST", {})[0] == 403)
check("voice policy cannot fake speaker verifier", owner.call("/api/voice/policy", "PUT", {"mode": "trusted_only", "speaker_verification_available": True})[0] == 400)
check("explicit session voice can be restored", owner.call("/api/voice/policy", "PUT", {"mode": "authenticated_session"})[1]["session_allowed"] is True)

if args.live_ai:
    status, voice = owner.call("/api/voice/session", "POST", {})
    check("provider issues configured realtime session", status == 200 and (isinstance(voice.get("value"), str) or isinstance(voice.get("client_secret", {}).get("value"), str)))
    status, response = owner.call("/api/chat", "POST", {"message": "Give one safe next step for this fictional inventory.", "locale": "en", "session_id": chat["id"]})
    check("live provider reply attached to conversation", status == 200 and response["session_id"] == chat["id"] and response["verification"]["source"] == "live_provider")
    reopened = owner.call("/api/chat/sessions/" + chat["id"])[1]
    check("provider exchange persists on reopening", len(reopened["messages"]) == 1 and reopened["messages"][0]["answer"] == response["answer"])
    status, result = owner.call("/api/security/sessions/" + session["id"] + "/questions", "POST", {"question": "What evidence is missing to assess this recording?", "locale": "en", "mode": "ai"})
    check("live evidence advisor uses persisted evidence", status == 200 and result["questions"][0]["provenance"] == "live_provider_evidence_advisor")
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    pixels = b"".join(b"\0" + b"\x36\x78\xaf" * 128 for _ in range(128))
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 128, 128, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b"")
    status, result = owner.call("/api/media/analyze", "POST", {"kind": "video", "images": ["data:image/png;base64," + base64.b64encode(png).decode()], "locale": "en", "context": "Synthetic solid-color test frame; explain limitations."})
    check("real provider visual observations remain inconclusive", status == 200 and result["provider_assessment"] is True and result["authenticity_verified"] is False and result["deepfake_detection_performed"] is False)
check("drive file deletion", owner.call("/api/drive/" + file["id"], "DELETE")[1]["deleted"] is True)
check("integration deletion", owner.call("/api/integrations/" + integration["id"], "DELETE")[1]["deleted"] is True)
print(json.dumps({"passed": len(checks), "failed": 0, "checks": checks, "live_provider_calls": args.live_ai, "detection_accuracy_evaluated": False}, indent=2))
