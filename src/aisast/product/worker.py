from __future__ import annotations

import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from .client import Client
from .incremental import atomic_json
from .store import private_directory


def terminate(child):
    if child.poll() is not None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
    except ProcessLookupError:
        pass


def serve(root: Path, state: Path, url: str, token: str, settings: dict, once=False):
    private_directory(state)
    # Prevent multiple local processes from publishing inconsistent baselines.
    with (state / "worker.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("A worker is already serving this project on this machine")
        settings_path = state / "worker-settings.json"
        atomic_json(settings_path, settings)
        client = Client(url, token)
        pid = settings["project_id"]
        base = "/api/agent/" + pid
        print("Worker connected. Repository stays on this machine. Press Ctrl+C to stop.", flush=True)
        while True:
            job = client.request("POST", base + "/claim")["job"]
            if job is None:
                if once:
                    print("No queued scan.")
                    return
                time.sleep(5)
                continue
            jid = job["id"]
            run = private_directory(state / "runs" / jid)
            command = [sys.executable, "-m", "aisast.product.scan_job", "--root", str(root), "--state", str(state),
                       "--job", jid, "--settings", str(settings_path)]
            if job["full"]:
                command.append("--full")
            print("Processing scan " + jid, flush=True)
            heartbeat = base + "/jobs/" + jid + "/heartbeat"
            complete = base + "/jobs/" + jid + "/complete"
            error = None
            with (run / "worker.stdout.log").open("w") as stdout, (run / "worker.stderr.log").open("w") as stderr:
                child = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    last_contact = time.monotonic()
                    while True:
                        progress_path = run / "progress.json"
                        progress = json.loads(progress_path.read_text()) if progress_path.is_file() else {"stage": "starting"}
                        try:
                            response = client.request("POST", heartbeat, {"lease": job["lease"], "progress": progress})
                            last_contact = time.monotonic()
                            if response["cancel"]:
                                terminate(child)
                                error = "Cancellation requested"
                                break
                        except (RuntimeError, OSError) as exc:
                            # Never run beyond a lost lease and then publish stale results.
                            if time.monotonic() - last_contact >= 60:
                                terminate(child)
                                raise RuntimeError("Backend connection lost; scan stopped to preserve lease safety") from exc
                        if child.poll() is not None:
                            if child.returncode:
                                error_path = run / "error.json"
                                error = json.loads(error_path.read_text())["error"] if error_path.is_file() else "Worker subprocess failed; inspect local logs"
                            break
                        time.sleep(5)
                except BaseException:
                    terminate(child)
                    try:
                        client.request("POST", complete, {"lease": job["lease"], "error": "Worker interrupted; inspect local logs"})
                    except Exception:
                        pass  # Server lease expiration retains the failure; no baseline is committed.
                    raise
            payload = json.loads((run / "result.json").read_text()) if not error else {}
            result = client.request("POST", complete, {"lease": job["lease"], "payload": payload, "error": error})
            if result["status"] == "completed":
                next_baseline = json.loads((run / "next-baseline.json").read_text())
                atomic_json(state / "baseline.json", next_baseline)
            print("Scan " + jid + ": " + result["status"], flush=True)
            if once:
                return
