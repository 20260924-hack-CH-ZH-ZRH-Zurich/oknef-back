"""Controlled upstream failure against real Rust/SQLite services, without provider credentials."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.cookiejar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--backend-binary", required=True)
parser.add_argument("--database-binary", required=True)
parser.add_argument("--output-dir", required=True)
args = parser.parse_args()
output = Path(args.output_dir)
output.mkdir(parents=True, exist_ok=True)
checks, processes = [], []
reached, release = threading.Event(), threading.Event()


class FailureGateway(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", "0")))
        reached.set()
        release.wait(timeout=10)
        self.send_response(502)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":"private-upstream-marker","private_key":"synthetic-secret-must-never-be-stored"}')


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


db_port, back_port = port(), port()
origin = f"http://localhost:{back_port}"
base = f"http://127.0.0.1:{back_port}"
gateway = ThreadingHTTPServer(("127.0.0.1", 0), FailureGateway)
threading.Thread(target=gateway.serve_forever, daemon=True).start()
token = secrets.token_urlsafe(40)


class Client:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, path, body=None):
        req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
            headers={"content-type": "application/json", "origin": origin})
        try:
            with self.opener.open(req, timeout=30) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)


def check(name, condition):
    checks.append({"test": name, "passed": bool(condition)})
    if not condition:
        raise AssertionError(name)


def start(binary, env, name, health):
    log = open(output / (name + ".log"), "wb")
    processes.append(subprocess.Popen([str(Path(binary).resolve())], cwd=output,
        env={"PATH": os.environ["PATH"], **env}, stdout=log, stderr=subprocess.STDOUT))
    for _ in range(100):
        try:
            with urllib.request.urlopen(health, timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.HTTPError):
            time.sleep(.05)
    raise RuntimeError("Test service did not become healthy")


try:
    start(args.database_binary, {"HTTP_BIND": f"127.0.0.1:{db_port}", "DATABASE_URL": f"sqlite://{output}/data.sqlite?mode=rwc", "DB_SERVICE_TOKEN": token}, "database", f"http://127.0.0.1:{db_port}/health")
    start(args.backend_binary, {"HTTP_BIND": f"127.0.0.1:{back_port}", "DATABASE_SERVICE_URL": f"http://127.0.0.1:{db_port}",
        "DB_SERVICE_TOKEN": token, "AI_CORE_URL": f"http://127.0.0.1:{gateway.server_port}", "AI_CORE_GRPC_URL": f"http://127.0.0.1:{gateway.server_port}", "AI_CORE_TOKEN": token,
        "PUBLIC_ORIGIN": origin, "COOKIE_SECURE": "false", "DEMO_ENABLED": "true", "DEMO_EMAIL": "audit@example.test", "DEMO_PASSWORD": secrets.token_urlsafe(24),
        "COVENANT_URL": f"http://127.0.0.1:{gateway.server_port}", "COVENANT_TOKEN": token}, "backend", base + "/health")
    owner, stranger = Client(), Client()
    owner_user = owner.call("/api/auth/demo", {"mode": "company"})[1]["user"]
    stranger.call("/api/auth/demo", {"mode": "admin"})
    status, _ = owner.call("/api/workflows", {"workflow": "unknown-review", "locale": "en", "message": "Synthetic invalid workflow."})
    check("unknown workflow rejected before provider call", status == 400 and not reached.is_set())
    check("unknown workflow cannot poison audit history", owner.call("/api/workflows/runs")[1]["runs"] == [])
    with ThreadPoolExecutor(max_workers=1) as executor:
        task = executor.submit(owner.call, "/api/workflows", {"workflow": "advisor-review", "locale": "en", "message": "Synthetic confidential evidence for a controlled error."})
        check("upstream was reached", reached.wait(timeout=10))
        pending = owner.call("/api/workflows/runs")[1]["runs"]
        check("pending run exists before provider completes", len(pending) == 1 and pending[0]["run_state"] == "pending")
        check("run actor is authenticated account", pending[0]["created_by"] == owner_user["id"])
        check("raw workflow input is not retained", "message" not in pending[0] and len(pending[0]["input_sha256"]) == 64)
        check("foreign admin demo cannot see pending run", stranger.call("/api/workflows/runs")[1]["runs"] == [])
        release.set()
        status, response = task.result(timeout=30)
    check("provider failure remains an HTTP error", status == 502)
    failed = owner.call("/api/workflows/runs")[1]["runs"]
    check("same durable run transitions to failed", len(failed) == 1 and failed[0]["id"] == pending[0]["id"] and failed[0]["run_state"] == "failed")
    check("failure retains safe code and upstream status", failed[0]["error_code"] == "workflow_provider_unavailable" and failed[0]["upstream_status"] == 502)
    check("failed run has completion timestamp", isinstance(failed[0]["completed_at"], int))
    check("no raw upstream secrets reach record or error", all(marker not in json.dumps([failed, response]) for marker in ["private-upstream-marker", "synthetic-secret-must-never-be-stored"]))
    check("foreign tenant cannot view failed history", stranger.call("/api/workflows/runs")[1]["runs"] == [])
    check("failure never invents executed actions", failed[0]["executed_actions"] == [])
finally:
    release.set()
    gateway.shutdown()
    for process in reversed(processes):
        process.terminate()
        process.wait(timeout=10)
    report = {"checks": checks, "passed": sum(item["passed"] for item in checks), "failed": sum(not item["passed"] for item in checks), "evidence_kind": "controlled_failure_real_Rust_SQLite_boundary_test", "live_provider": False}
    (output / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
