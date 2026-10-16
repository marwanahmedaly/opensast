from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import sys
import time
import webbrowser
from pathlib import Path
import httpx
import yaml
from urllib.parse import urlsplit

from .client import Client, validate_url
from .incremental import atomic_json
from .store import AccessError, Store, private_directory, state_home


def credentials_file():
    return private_directory(state_home() / "client") / "credentials.json"


def read_json(path):
    return json.loads(path.read_text()) if path.is_file() else {}


def project_config():
    path = Path.cwd() / ".opensast/config.json"
    if not path.is_file():
        raise RuntimeError("Run opensast init at this project's root first")
    return read_json(path)


def client(args, project=False):
    credentials = read_json(credentials_file())
    url = args.server or (project_config()["server"] if project else credentials.get("server"))
    if not url:
        raise RuntimeError("Run opensast login --server URL first")
    if credentials.get("server") != url.rstrip("/"):
        raise RuntimeError("Log in to this project's backend first")
    return Client(url, credentials.get("token", ""))


def show(value):
    print(json.dumps(value, indent=2))


def workspace_choice(api, requested=None):
    workspaces = api.request("GET", "/api/workspaces")
    if not workspaces:
        raise RuntimeError("Create a workspace first: opensast workspace create NAME")
    if requested is None and len(workspaces) == 1:
        return workspaces[0]["id"]
    if requested is None:
        for index, workspace in enumerate(workspaces, start=1):
            print(f"{index}. {workspace['name']}  ({workspace['role']})  {workspace['id']}")
        requested = input(f"Choose workspace [1–{len(workspaces)}], name, or ID: ").strip()
    else:
        requested = requested.strip()
    by_id = next((workspace for workspace in workspaces if workspace["id"] == requested), None)
    if by_id:
        return by_id["id"]
    by_name = [workspace for workspace in workspaces if workspace["name"] == requested]
    if len(by_name) == 1:
        return by_name[0]["id"]
    if len(by_name) > 1:
        raise RuntimeError("Several workspaces have this name; choose their displayed number or exact ID")
    if requested.isdecimal():
        choice = int(requested)
        if 1 <= choice <= len(workspaces):
            return workspaces[choice - 1]["id"]
    raise RuntimeError(f"Invalid workspace selection. Choose 1–{len(workspaces)}, an accessible workspace name, or its ID")


def initialize(args):
    root = Path.cwd().resolve()
    if not any((root / name).exists() for name in ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt")) and not any(root.rglob("*.py")):
        raise RuntimeError("This directory does not appear to be a Python project")
    api = client(args)
    path = root / ".opensast/config.json"
    if path.exists():
        config = read_json(path)
        if config["server"] != api.url:
            raise RuntimeError("Project is already registered with another backend")
        accessible = api.request("GET", "/api/projects")
        if not any(p["id"] == config["project_id"] for p in accessible):
            raise RuntimeError("You do not have access to this registered project")
        if args.project and args.project != config["project_id"]:
            raise RuntimeError("Project is already registered with a different ID")
        project = {"id": config["project_id"]}
    elif args.project:
        accessible = api.request("GET", "/api/projects")
        project = next((p for p in accessible if p["id"] == args.project), None)
        if not project:
            raise RuntimeError("Project is not accessible")
    else:
        wid = workspace_choice(api, args.workspace)
        project = api.request("POST", "/api/projects", {"workspace_id": wid, "name": args.name or root.name})
    private_directory(path.parent)
    atomic_json(path, {"version": 1, "server": api.url, "project_id": project["id"]})
    (path.parent / ".gitignore").write_text("*\n")
    # Ignore the directory itself as well, while preserving existing project ignore rules.
    ignore = root / ".gitignore"
    text = ignore.read_text() if ignore.is_file() else ""
    if "/.opensast/" not in text.splitlines():
        with ignore.open("a") as stream:
            stream.write(("\n" if text and not text.endswith("\n") else "") + "/.opensast/\n")
    dashboard = api.url + "/#project=" + project["id"]
    print("Registered project " + project["id"] + "\nDashboard: " + dashboard)
    from aisast.install.setup import load_settings
    installed = load_settings()
    if installed and not getattr(args, 'no_worker', False):
        state = private_directory(state_home() / 'workers' / project['id'])
        credential_path = state / 'credentials.json'
        current = read_json(credential_path)
        try:
            if not current.get('token') or current.get('server') != api.url:
                value = api.request('POST', '/api/projects/' + project['id'] + '/worker-token')
                atomic_json(credential_path, {'server': api.url, 'token': value['token']})
            from aisast.install.services import start_worker
            start_worker(root, {'project_id': project['id']}, installed)
        except RuntimeError as exc:
            print('Project registered; worker could not start: ' + str(exc), file=sys.stderr)
            print('An administrator can provision it using opensast worker-token, then opensast worker.', file=sys.stderr)
    if not args.no_browser:
        webbrowser.open(dashboard)


def main():
    parser = argparse.ArgumentParser(prog="opensast", description="Self-hosted Python security analysis")
    parser.add_argument("--server", help="Internal backend URL; normally remembered by login/init")
    commands = parser.add_subparsers(dest="command", required=True)
    from aisast.install.setup import parser as installation_parser
    installation_parser(commands)
    p = commands.add_parser("bootstrap", help="Provision the initial account on the backend machine")
    p.add_argument("--username", required=True); p.add_argument("--workspace", default="Personal")
    p.add_argument("--data", type=Path)
    p = commands.add_parser("serve", help="Run the internal API and dashboard")
    p.add_argument("--data", type=Path); p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8765)
    p.add_argument("--public-url", help="Exact browser origin; HTTPS required for a company deployment")
    p.add_argument("--trusted-origin", action="append", default=[], help="Additional exact HTTPS origin, or private Tailscale HTTP IP origin")
    p = commands.add_parser("login"); p.add_argument("--username", required=True)
    commands.add_parser("logout")
    commands.add_parser("password")
    p = commands.add_parser("init"); p.add_argument("--workspace"); p.add_argument("--name"); p.add_argument("--project")
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--no-worker", action="store_true", help="Register only; do not start a worker from saved installation settings")
    commands.add_parser("projects")
    commands.add_parser("dashboard")
    p = commands.add_parser("workspace"); sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("list"); q = sub.add_parser("create"); q.add_argument("name")
    p = commands.add_parser("members"); p.add_argument("workspace"); p.add_argument("--username")
    p.add_argument("--role", choices=["admin", "member", "viewer", "remove"]); p.add_argument("--new-user", action="store_true")
    p = commands.add_parser("audit"); p.add_argument("workspace")
    p = commands.add_parser("scan"); p.add_argument("--full", action="store_true"); p.add_argument("--wait", action="store_true")
    p = commands.add_parser("status"); p.add_argument("--job")
    p = commands.add_parser("cancel"); p.add_argument("job")
    p = commands.add_parser("findings"); p.add_argument("job")
    p = commands.add_parser("export"); p.add_argument("job"); p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("review"); p.add_argument("job"); p.add_argument("finding")
    p.add_argument("state", choices=["open", "confirmed", "dismissed"]); p.add_argument("--note", default="")
    p = commands.add_parser("worker-token", help="Rotate or import this project's worker token")
    p.add_argument("--import", dest="import_token", action="store_true", help="Privately paste an admin-provisioned token")
    p = commands.add_parser("worker", help="Serve queued jobs using this machine's registered checkout")
    p.add_argument("--once", action="store_true"); p.add_argument("--codeql", default=None)
    p.add_argument("--query-search-path", type=Path, help="Preinstalled packs; defaults to saved setup; no scan-time downloads")
    p.add_argument("--endpoint", help="Internal OpenAI-compatible inference URL, e.g. http://127.0.0.1:8000/v1")
    p.add_argument("--model"); p.add_argument("--model-revision", help="Pinned weight digest/revision; required for LLM cache reuse")
    p.add_argument("--allow-model-host", action="append", default=None, help="Explicit company-internal inference hostname")
    p.add_argument("--context-window", type=int); p.add_argument("--max-tokens", type=int)
    p.add_argument("--suspect-only", action="store_true", help="Omit verification, including any saved model configuration")
    p = commands.add_parser("ci", help="Git-aware local/CI scan without dashboard authentication")
    p.add_argument("--base", help="PR target revision; compares its merge-base with the current working tree")
    p.add_argument("--project-key", required=True, help="Stable repository identifier, e.g. company/project")
    p.add_argument("--state", type=Path, required=True, help="Private reusable cache outside the checkout")
    p.add_argument("--output", type=Path, required=True, help="Full JSON report outside the checkout")
    p.add_argument("--full", action="store_true")
    p.add_argument("--fail-on", choices=["new", "none"], default="new")
    p.add_argument("--codeql", default=None)
    p.add_argument("--query-search-path", type=Path)
    p.add_argument("--endpoint"); p.add_argument("--model")
    p.add_argument("--model-revision", help="Pinned weight digest/revision for cache identity; defaults to saved setup")
    p.add_argument("--allow-model-host", action="append", default=None)
    p.add_argument("--context-window", type=int)
    p.add_argument("--max-tokens", type=int)
    for command_parser in commands.choices.values():
        command_parser.add_argument("--server", default=argparse.SUPPRESS, help="Internal backend URL")
    args = parser.parse_args()
    try:
        if args.command in {'setup', 'doctor', 'start', 'stop', 'restart'}:
            from aisast.install.setup import configure, doctor, load_settings
            from aisast.install.services import start, stop
            if args.command == 'setup':
                return configure(args)
            if args.command == 'doctor':
                return doctor()
            if args.command == 'stop':
                stop()
                return 0
            settings = load_settings()
            if not settings:
                raise RuntimeError('Run opensast setup first.')
            if args.command == 'restart':
                stop()
            start(settings)
            return 0
        if args.command in {'worker', 'ci'}:
            from aisast.install.setup import apply_engine_defaults
            apply_engine_defaults(args)
            if not args.query_search_path:
                raise RuntimeError('Run opensast setup or provide --query-search-path to preinstalled packs.')
        if args.command == "bootstrap":
            password = getpass.getpass("Initial password (at least 12 characters): ")
            if password != getpass.getpass("Repeat password: "):
                raise RuntimeError("Passwords do not match")
            show(Store(args.data or state_home() / "server").bootstrap(args.username, password, args.workspace))
        elif args.command == "serve":
            try:
                import uvicorn
                from .api import create_app
            except ImportError:
                raise RuntimeError('Install the web extra first: pip install -e ".[web]"')
            url = args.public_url or f"http://{args.host}:{args.port}"
            validate_url(url, allowed_hosts=None)
            if urlsplit(url).path not in {"", "/"}:
                raise RuntimeError("Public URL must be an origin without a path")
            if args.host not in {"127.0.0.1", "localhost", "::1"} and not (args.public_url and url.startswith("https://")):
                raise RuntimeError("Network binding requires --public-url https://YOUR-INTERNAL-HOST and an internal TLS reverse proxy")
            for trusted in args.trusted_origin:
                parsed = urlsplit(trusted)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
                    raise RuntimeError("Trusted origin must be an exact HTTP(S) origin without credentials or a path")
                if parsed.scheme == "http":
                    try:
                        tailnet = ipaddress.ip_address(parsed.hostname) in ipaddress.ip_network("100.64.0.0/10")
                    except ValueError:
                        tailnet = False
                    if not tailnet:
                        raise RuntimeError("Additional HTTP origins must use an explicitly selected private Tailscale IP")
            uvicorn.run(create_app(args.data or state_home() / "server", url, args.trusted_origin), host=args.host, port=args.port,
                        proxy_headers=False, access_log=False, workers=1)
        elif args.command == "login":
            url = args.server or "http://127.0.0.1:8765"
            value = Client(url).request("POST", "/api/login", {"username": args.username, "password": getpass.getpass("Password: ")})
            atomic_json(credentials_file(), {"server": url.rstrip("/"), "token": value["token"]})
            print("Logged in as " + value["username"])
        elif args.command == "logout":
            api = client(args)
            api.request("POST", "/api/logout")
            credentials_file().unlink(missing_ok=True)
            print("Logged out")
        elif args.command == "password":
            api = client(args)
            old = getpass.getpass("Current password: ")
            new = getpass.getpass("New password (at least 12 characters): ")
            if new != getpass.getpass("Repeat new password: "):
                raise RuntimeError("Passwords do not match")
            api.request("POST", "/api/password", {"old_password": old, "new_password": new})
            credentials_file().unlink(missing_ok=True)
            print("Password changed. All sessions revoked; log in again.")
        elif args.command == "init":
            initialize(args)
        elif args.command == "ci":
            from .ci import run
            if not args.endpoint or not args.model:
                raise RuntimeError("CI verification needs a saved model setup or explicit --endpoint and --model.")
            if not args.query_search_path.is_dir():
                raise RuntimeError("Query search path must be a preinstalled local pack directory")
            if args.context_window <= args.max_tokens + 64 or args.max_tokens < 1:
                raise RuntimeError("Invalid token budget")
            if not args.model_revision or not args.model_revision.strip():
                raise RuntimeError("A nonempty model revision is required")
            settings = {"project_id": args.project_key, "codeql": args.codeql,
                        "query_search_path": str(args.query_search_path.resolve()),
                        "endpoint": validate_url(args.endpoint, args.allow_model_host),
                        "model": args.model, "model_revision": args.model_revision,
                        "context_window": args.context_window, "max_tokens": args.max_tokens}
            return run(args, settings)
        elif args.command == "worker":
            from .worker import serve
            config = project_config()
            pid = config["project_id"]
            state = private_directory(state_home() / "workers" / pid)
            worker_config = read_json(state / "credentials.json")
            if not worker_config.get("token") or worker_config.get("server") != config["server"]:
                raise RuntimeError("An admin must provision credentials here using opensast worker-token")
            if bool(args.endpoint) != bool(args.model):
                raise RuntimeError("Provide both --endpoint and --model, or omit both for suspect-only scans")
            if args.context_window <= args.max_tokens + 64 or args.max_tokens < 1:
                raise RuntimeError("Invalid token budget")
            if not args.query_search_path.is_dir():
                raise RuntimeError("Query search path must be a preinstalled local pack directory")
            settings = {"project_id": pid, "codeql": args.codeql, "query_search_path": str(args.query_search_path.resolve()),
                        "endpoint": validate_url(args.endpoint, args.allow_model_host) if args.endpoint else None,
                        "model": args.model, "model_revision": args.model_revision,
                        "context_window": args.context_window, "max_tokens": args.max_tokens}
            serve(Path.cwd().resolve(), state, config["server"], worker_config["token"], settings, args.once)
        elif args.command == "worker-token":
            config = project_config()
            if args.import_token:
                value = {"token": getpass.getpass("Project worker token: ")}
                if not value["token"]:
                    raise RuntimeError("Worker token is empty")
            else:
                api = client(args, project=True)
                value = api.request("POST", "/api/projects/" + config["project_id"] + "/worker-token")
            state = private_directory(state_home() / "workers" / config["project_id"])
            atomic_json(state / "credentials.json", {"server": config["server"], "token": value["token"]})
            print("Worker token saved privately. Restart the worker to use it.")
        else:
            project_action = args.command in {"scan", "status", "dashboard"}
            api = client(args, project=project_action)
            if args.command == "projects":
                show(api.request("GET", "/api/projects"))
            elif args.command == "workspace":
                show(api.request("GET", "/api/workspaces") if args.action == "list" else api.request("POST", "/api/workspaces", {"name": args.name}))
            elif args.command == "members":
                if args.username:
                    if not args.role:
                        raise RuntimeError("Choose --role for membership changes")
                    value = {"username": args.username, "role": None if args.role == "remove" else args.role}
                    if args.new_user:
                        value["password"] = getpass.getpass("New user's initial password: ")
                    show(api.request("POST", "/api/workspaces/" + args.workspace + "/members", value))
                else:
                    show(api.request("GET", "/api/workspaces/" + args.workspace + "/members"))
            elif args.command == "audit":
                show(api.request("GET", "/api/workspaces/" + args.workspace + "/audit"))
            elif args.command == "scan":
                job = api.request("POST", "/api/projects/" + project_config()["project_id"] + "/jobs", {"full": args.full})
                show(job)
                if args.wait:
                    print("Waiting for the project's worker. Run opensast worker if it is offline.", file=sys.stderr)
                    while True:
                        value = api.request("GET", "/api/jobs/" + job["id"])
                        if value["status"] not in {"queued", "running"}:
                            show(value)
                            if value["status"] != "completed":
                                return 1
                            result = api.request("GET", "/api/jobs/" + job["id"] + "/results")
                            if result["summary"].get("verifier_configured") and any(
                                finding["verdict"] in {"SYSTEM_ERROR", "UNRESOLVED", "NEEDS_MORE_CONTEXT"}
                                for finding in result["findings"]
                            ):
                                print("Verification incomplete; inspect findings and restore inference or evidence before rescanning.", file=sys.stderr)
                                return 2
                            break
                        time.sleep(5)
            elif args.command == "status":
                show(api.request("GET", "/api/jobs/" + args.job) if args.job else api.request("GET", "/api/projects/" + project_config()["project_id"] + "/jobs"))
            elif args.command == "cancel":
                show(api.request("POST", "/api/jobs/" + args.job + "/cancel"))
            elif args.command == "findings":
                show(api.request("GET", "/api/jobs/" + args.job + "/results"))
            elif args.command == "export":
                atomic_json(args.output, api.request("GET", "/api/jobs/" + args.job + "/export"))
                print(args.output)
            elif args.command == "review":
                show(api.request("POST", f"/api/jobs/{args.job}/findings/{args.finding}/review", {"state": args.state, "note": args.note}))
            elif args.command == "dashboard":
                webbrowser.open(api.url + "/#project=" + project_config()["project_id"])
        return 0
    except (AccessError, RuntimeError, ValueError, OSError, httpx.HTTPError, KeyError, yaml.YAMLError) as exc:
        if args.command == 'setup':
            try:
                from aisast.install.setup import audit
                audit('setup_failed', error=str(exc))
            except OSError:
                pass
        print("OpenSAST: " + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Stopped.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
