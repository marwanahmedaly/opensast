from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field, ConfigDict

from .store import AccessError, SESSION_SECONDS, Store


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(Body):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class PasswordChange(Body):
    old_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


class Named(Body):
    name: str = Field(min_length=1, max_length=200)


class Project(Named):
    workspace_id: str


class Member(Body):
    username: str = Field(min_length=1, max_length=128)
    role: Literal["admin", "member", "viewer"] | None = None
    password: str | None = Field(default=None, max_length=1024)


class Scan(Body):
    full: bool = False


class Review(Body):
    state: Literal["open", "confirmed", "dismissed"]
    note: str = Field(default="", max_length=10000)


class Heartbeat(Body):
    lease: str
    progress: dict = Field(default_factory=dict)


class Completion(Body):
    lease: str
    payload: dict = Field(default_factory=dict)
    error: str | None = None


def create_app(directory: Path, public_url: str, trusted_origins: list[str] | None = None):
    store = Store(directory)
    origin = public_url.rstrip("/")
    secure = urlsplit(origin).scheme == "https"
    parsed_origin = urlsplit(origin)
    allowed_hosts = {parsed_origin.netloc.lower()}
    allowed_origins = {origin}
    if parsed_origin.hostname in {"127.0.0.1", "localhost", "::1"}:
        port = ":" + str(parsed_origin.port) if parsed_origin.port is not None else ""
        for hostname in ("127.0.0.1", "localhost", "[::1]"):
            allowed_hosts.add(hostname + port)
            allowed_origins.add(parsed_origin.scheme + "://" + hostname + port)
    for trusted in trusted_origins or []:
        allowed_origins.add(trusted.rstrip("/"))
        allowed_hosts.add(urlsplit(trusted).netloc.lower())
    app = FastAPI(title="OpenSAST", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    failures = defaultdict(deque)
    throttle_lock = threading.Lock()
    assets = Path(__file__).parent / "static"

    @app.exception_handler(AccessError)
    async def denied(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    @app.middleware("http")
    async def security(request, call_next):
        # Host validation prevents DNS-rebinding access to a loopback installation.
        if request.headers.get("host", "").lower() not in allowed_hosts:
            logging.getLogger("uvicorn.error").warning("Rejected dashboard Host: %r", request.headers.get("host", "")[:250])
            return JSONResponse({"detail": "Unexpected host. Open the configured dashboard address: " + origin}, status_code=400)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            browser_origin = request.headers.get("origin")
            if browser_origin and browser_origin not in allowed_origins:
                return JSONResponse({"detail": "Unexpected origin"}, status_code=403)
            if request.cookies.get("opensast_session") and not request.headers.get("authorization"):
                if browser_origin not in allowed_origins or request.headers.get("x-opensast-csrf") != "1":
                    return JSONResponse({"detail": "Browser request requires CSRF protection"}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        if secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    def token(request: Request):
        authorization = request.headers.get("authorization", "")
        if authorization.startswith("Bearer "):
            return authorization[7:]
        return request.cookies.get("opensast_session", "")

    def user(request: Request):
        return store.user(token(request))["id"]

    def worker(request: Request):
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer "):
            raise AccessError("Worker authentication required", 401)
        return authorization[7:]

    @app.get("/")
    @app.get("/scans/{jid}")
    @app.get("/scans/{jid}/findings/{fid}")
    def index():
        return FileResponse(assets / "index.html")

    @app.get("/assets/{filename}")
    def asset(filename: str):
        if filename not in {"app.js", "style.css"}:
            raise AccessError()
        return FileResponse(assets / filename)

    @app.get("/api/health")
    def health():
        return {"status": "ok", "deployment": "self-hosted"}

    @app.post("/api/login")
    def login(body: Login, request: Request):
        # Do not trust proxy headers for rate-limit identity.
        peer = request.client.host if request.client else "local"
        keys = [("peer", peer), ("user", body.username)]
        now = time.monotonic()
        with throttle_lock:
            for key in list(failures):
                while failures[key] and failures[key][0] < now - 300:
                    failures[key].popleft()
                if not failures[key]:
                    del failures[key]
            if len(failures) > 10000:
                raise AccessError("Login service is busy; retry later", 429)
            for key, limit in zip(keys, (100, 5)):
                if len(failures[key]) >= limit:
                    raise AccessError("Too many login attempts; retry after five minutes", 429)
            for key in keys:
                failures[key].append(now)
        value = store.login(body.username, body.password)
        with throttle_lock:
            failures.pop(keys[1], None)
        # Browser receives an HttpOnly cookie; CLI receives the bearer credential.
        is_browser = request.headers.get("origin") is not None
        response = JSONResponse({k: v for k, v in value.items() if k != "token"} if is_browser else value)
        if is_browser:
            response.set_cookie("opensast_session", value["token"], httponly=True, secure=secure,
                                samesite="strict", max_age=SESSION_SECONDS, path="/")
        return response

    @app.post("/api/logout")
    def logout(request: Request, uid=Depends(user)):
        store.logout(token(request))
        response = JSONResponse({"logged_out": True})
        response.delete_cookie("opensast_session", path="/")
        return response

    @app.post("/api/password")
    def password(body: PasswordChange, uid=Depends(user)):
        value = store.change_password(uid, body.old_password, body.new_password)
        response = JSONResponse(value)
        response.delete_cookie("opensast_session", path="/")
        return response

    @app.get("/api/me")
    def me(request: Request, uid=Depends(user)):
        return store.user(token(request))

    @app.get("/api/workspaces")
    def workspaces(uid=Depends(user)):
        return store.workspaces(uid)

    @app.post("/api/workspaces")
    def create_workspace(body: Named, uid=Depends(user)):
        return store.create_workspace(uid, body.name)

    @app.get("/api/workspaces/{wid}/members")
    def members(wid: str, uid=Depends(user)):
        return store.members(uid, wid)

    @app.post("/api/workspaces/{wid}/members")
    def member(wid: str, body: Member, uid=Depends(user)):
        return store.set_member(uid, wid, body.username, body.role, body.password)

    @app.get("/api/workspaces/{wid}/audit")
    def audit(wid: str, uid=Depends(user)):
        return store.audit_rows(uid, wid)

    @app.get("/api/projects")
    def projects(uid=Depends(user)):
        return store.projects(uid)

    @app.post("/api/projects")
    def create_project(body: Project, uid=Depends(user)):
        return store.create_project(uid, body.workspace_id, body.name)

    @app.post("/api/projects/{pid}/worker-token")
    def rotate(pid: str, uid=Depends(user)):
        return store.rotate_worker(uid, pid)

    @app.get("/api/projects/{pid}/jobs")
    def jobs(pid: str, uid=Depends(user)):
        return store.jobs(uid, pid)

    @app.post("/api/projects/{pid}/jobs")
    def scan(pid: str, body: Scan, uid=Depends(user)):
        return store.enqueue(uid, pid, body.full)

    @app.get("/api/jobs/{jid}")
    def job(jid: str, uid=Depends(user)):
        return store.job(uid, jid)

    @app.post("/api/jobs/{jid}/cancel")
    def cancel(jid: str, uid=Depends(user)):
        return store.cancel(uid, jid)

    @app.get("/api/jobs/{jid}/results")
    def results(jid: str, uid=Depends(user)):
        return store.result(uid, jid)

    @app.get("/api/jobs/{jid}/export")
    def export(jid: str, uid=Depends(user)):
        return Response(json.dumps(store.result(uid, jid), indent=2), media_type="application/json",
                        headers={"Content-Disposition": 'attachment; filename="opensast-' + jid + '.json"'})

    @app.post("/api/jobs/{jid}/findings/{fid}/review")
    def review(jid: str, fid: str, body: Review, uid=Depends(user)):
        return store.review(uid, jid, fid, body.state, body.note)

    @app.post("/api/agent/{pid}/claim")
    def claim(pid: str, auth=Depends(worker)):
        return {"job": store.claim(pid, auth)}

    @app.post("/api/agent/{pid}/jobs/{jid}/heartbeat")
    def heartbeat(pid: str, jid: str, body: Heartbeat, auth=Depends(worker)):
        return store.heartbeat(pid, auth, jid, body.lease, body.progress)

    @app.post("/api/agent/{pid}/jobs/{jid}/complete")
    def complete(pid: str, jid: str, body: Completion, auth=Depends(worker)):
        return store.complete(pid, auth, jid, body.lease, body.payload, body.error)

    return app
