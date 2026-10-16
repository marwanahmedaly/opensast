from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

ROLES = {"admin": 2, "member": 1, "viewer": 0}
SESSION_SECONDS = 12 * 3600
LEASE_SECONDS = 180


class AccessError(Exception):
    def __init__(self, message="Not found", status=404):
        super().__init__(message)
        self.status = status


def private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def state_home() -> Path:
    return Path(os.environ.get("OPENSAST_HOME", "~/.local/share/opensast")).expanduser()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password: str, salt: str | None = None) -> str:
    if not 12 <= len(password) <= 1024:
        raise AccessError("Password must have 12–1024 characters", 400)
    salt = salt or secrets.token_hex(16)
    value = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000)
    return salt + ":" + value.hex()


def valid_password(password: str, stored: str) -> bool:
    if not 12 <= len(password) <= 1024:
        return False
    salt = stored.split(":", 1)[0]
    return hmac.compare_digest(password_hash(password, salt), stored)


class Store:
    def __init__(self, directory: Path):
        self.directory = private_directory(directory)
        self.path = directory / "opensast.sqlite3"
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS workspaces(id TEXT PRIMARY KEY, name TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS memberships(workspace_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL,
                    PRIMARY KEY(workspace_id,user_id));
                CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, name TEXT NOT NULL,
                    created REAL NOT NULL, worker_token TEXT, worker_seen REAL);
                CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, requested_by TEXT NOT NULL,
                    status TEXT NOT NULL, full INTEGER NOT NULL, created REAL NOT NULL, started REAL, finished REAL,
                    heartbeat REAL, lease TEXT, progress TEXT NOT NULL DEFAULT '{}', error TEXT, cancel INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS results(job_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS triage(project_id TEXT NOT NULL, finding_id TEXT NOT NULL, state TEXT NOT NULL,
                    note TEXT NOT NULL, user_id TEXT NOT NULL, updated REAL NOT NULL, PRIMARY KEY(project_id,finding_id));
                CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
                    actor TEXT NOT NULL, workspace_id TEXT, action TEXT NOT NULL, target TEXT NOT NULL);
            """)
        self.path.chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def audit(self, db, actor, workspace, action, target):
        db.execute("INSERT INTO audit(at,actor,workspace_id,action,target) VALUES(?,?,?,?,?)",
                   (time.time(), actor, workspace, action, target))

    def bootstrap(self, username, password, workspace):
        if not username.strip() or len(username) > 128 or not workspace.strip() or len(workspace) > 200:
            raise AccessError("Invalid username or workspace name", 400)
        uid, wid = secrets.token_hex(16), secrets.token_hex(16)
        hashed = password_hash(password)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                raise AccessError("Installation already initialized", 409)
            db.execute("INSERT INTO users VALUES(?,?,?)", (uid, username, hashed))
            db.execute("INSERT INTO workspaces VALUES(?,?)", (wid, workspace))
            db.execute("INSERT INTO memberships VALUES(?,?,?)", (wid, uid, "admin"))
            self.audit(db, uid, wid, "bootstrap", wid)
        return {"username": username, "workspace_id": wid}

    def login(self, username, password):
        with self.connect() as db:
            row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            # Do equal password work when the username is unknown.
            stored = row["password"] if row else "00" * 16 + ":" + "00" * 32
            ok = valid_password(password, stored)
            if not row or not ok:
                raise AccessError("Invalid credentials", 401)
            token = secrets.token_urlsafe(40)
            db.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
            db.execute("INSERT INTO sessions VALUES(?,?,?)", (digest(token), row["id"], time.time() + SESSION_SECONDS))
            self.audit(db, row["id"], None, "login", row["id"])
            return {"token": token, "username": username, "expires_in": SESSION_SECONDS}

    def user(self, token):
        with self.connect() as db:
            row = db.execute("SELECT u.id,u.username FROM users u JOIN sessions s ON s.user_id=u.id "
                             "WHERE s.token=? AND s.expires>?", (digest(token), time.time())).fetchone()
            if not row:
                raise AccessError("Login required", 401)
            return dict(row)

    def logout(self, token):
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE token=?", (digest(token),))

    def change_password(self, uid, old_password, new_password):
        hashed = password_hash(new_password)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT password FROM users WHERE id=?", (uid,)).fetchone()
            if not row or not valid_password(old_password, row[0]):
                raise AccessError("Invalid current password", 403)
            db.execute("UPDATE users SET password=? WHERE id=?", (hashed, uid))
            db.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
            self.audit(db, uid, None, "password.change", uid)
        return {"password_changed": True, "login_required": True}

    def workspace_access(self, db, uid, wid, role="viewer"):
        row = db.execute("SELECT role FROM memberships WHERE workspace_id=? AND user_id=?", (wid, uid)).fetchone()
        if not row:
            raise AccessError()
        if ROLES[row["role"]] < ROLES[role]:
            raise AccessError("Insufficient permissions", 403)
        return row["role"]

    def project_access(self, db, uid, pid, role="viewer"):
        row = db.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
        if not row:
            raise AccessError()
        self.workspace_access(db, uid, row["workspace_id"], role)
        return row

    def workspaces(self, uid):
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT w.*,m.role FROM workspaces w JOIN memberships m "
                                                "ON m.workspace_id=w.id WHERE m.user_id=? ORDER BY w.name", (uid,))]

    def create_workspace(self, uid, name):
        wid = secrets.token_hex(16)
        with self.connect() as db:
            db.execute("INSERT INTO workspaces VALUES(?,?)", (wid, name))
            db.execute("INSERT INTO memberships VALUES(?,?,?)", (wid, uid, "admin"))
            self.audit(db, uid, wid, "workspace.create", wid)
        return {"id": wid, "name": name, "role": "admin"}

    def members(self, uid, wid):
        with self.connect() as db:
            self.workspace_access(db, uid, wid)
            return [dict(r) for r in db.execute("SELECT u.username,m.role FROM memberships m JOIN users u "
                                                "ON u.id=m.user_id WHERE m.workspace_id=?", (wid,))]

    def set_member(self, uid, wid, username, role, password=None):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.workspace_access(db, uid, wid, "admin")
            user = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if not user:
                if role is None or password is None:
                    raise AccessError("New users require an initial password", 400)
                target = secrets.token_hex(16)
                db.execute("INSERT INTO users VALUES(?,?,?)", (target, username, password_hash(password)))
            else:
                target = user["id"]
                if password:
                    raise AccessError("Existing accounts cannot have passwords replaced through membership", 409)
            old = db.execute("SELECT role FROM memberships WHERE workspace_id=? AND user_id=?", (wid, target)).fetchone()
            if old and old["role"] == "admin" and role != "admin":
                count = db.execute("SELECT count(*) FROM memberships WHERE workspace_id=? AND role='admin'", (wid,)).fetchone()[0]
                if count <= 1:
                    raise AccessError("Workspace must retain an admin", 409)
            if role is None:
                db.execute("DELETE FROM memberships WHERE workspace_id=? AND user_id=?", (wid, target))
            else:
                db.execute("INSERT OR REPLACE INTO memberships VALUES(?,?,?)", (wid, target, role))
            self.audit(db, uid, wid, "membership." + (role or "remove"), target)
        return {"username": username, "role": role}

    def projects(self, uid):
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT p.id,p.name,p.workspace_id,p.created,p.worker_seen,m.role "
                "FROM projects p JOIN memberships m ON m.workspace_id=p.workspace_id WHERE m.user_id=? ORDER BY p.created DESC", (uid,))]

    def create_project(self, uid, wid, name):
        pid = secrets.token_hex(16)
        with self.connect() as db:
            self.workspace_access(db, uid, wid, "admin")
            db.execute("INSERT INTO projects(id,workspace_id,name,created) VALUES(?,?,?,?)", (pid, wid, name, time.time()))
            self.audit(db, uid, wid, "project.create", pid)
        return {"id": pid, "workspace_id": wid, "name": name}

    def rotate_worker(self, uid, pid):
        token = secrets.token_urlsafe(40)
        with self.connect() as db:
            project = self.project_access(db, uid, pid, "admin")
            db.execute("UPDATE projects SET worker_token=? WHERE id=?", (digest(token), pid))
            self.audit(db, uid, project["workspace_id"], "worker.rotate", pid)
        return {"token": token}

    def expire_jobs(self, db):
        now = time.time()
        db.execute("UPDATE jobs SET status=CASE WHEN cancel=1 THEN 'cancelled' ELSE 'failed' END, finished=?,"
                   "error='Worker lease expired' WHERE status='running' AND heartbeat<?", (now, now - LEASE_SECONDS))

    def jobs(self, uid, pid):
        with self.connect() as db:
            self.project_access(db, uid, pid)
            self.expire_jobs(db)
            return [self.job_dict(r) for r in db.execute("SELECT * FROM jobs WHERE project_id=? ORDER BY created DESC", (pid,))]

    @staticmethod
    def job_dict(row):
        result = dict(row)
        result.pop("lease", None)
        result["progress"] = json.loads(result["progress"])
        return result

    def enqueue(self, uid, pid, full):
        jid = secrets.token_hex(16)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            project = self.project_access(db, uid, pid, "member")
            self.expire_jobs(db)
            if db.execute("SELECT 1 FROM jobs WHERE project_id=? AND status IN ('queued','running')", (pid,)).fetchone():
                raise AccessError("A scan is already queued or running for this project", 409)
            db.execute("INSERT INTO jobs(id,project_id,requested_by,status,full,created) VALUES(?,?,?,'queued',?,?)",
                       (jid, pid, uid, int(full), time.time()))
            self.audit(db, uid, project["workspace_id"], "job.queue", jid)
        return {"id": jid, "status": "queued"}

    def job_access(self, db, uid, jid, role="viewer"):
        row = db.execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
        if not row:
            raise AccessError()
        self.project_access(db, uid, row["project_id"], role)
        return row

    def job(self, uid, jid):
        with self.connect() as db:
            self.expire_jobs(db)
            return self.job_dict(self.job_access(db, uid, jid))

    def cancel(self, uid, jid):
        with self.connect() as db:
            job = self.job_access(db, uid, jid, "member")
            project = self.project_access(db, uid, job["project_id"])
            if job["status"] not in {"queued", "running"}:
                raise AccessError("Job is already finished", 409)
            db.execute("UPDATE jobs SET cancel=1,status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,"
                       "finished=CASE WHEN status='queued' THEN ? ELSE finished END WHERE id=?", (time.time(), jid))
            self.audit(db, uid, project["workspace_id"], "job.cancel", jid)
        return {"id": jid, "cancellation_requested": True}

    def result(self, uid, jid):
        with self.connect() as db:
            self.job_access(db, uid, jid)
            row = db.execute("SELECT payload FROM results WHERE job_id=?", (jid,)).fetchone()
            if not row:
                raise AccessError("Results are not available", 409)
            payload = json.loads(row["payload"])
            job = db.execute("SELECT project_id FROM jobs WHERE id=?", (jid,)).fetchone()
            reviews = {r["finding_id"]: dict(r) for r in db.execute("SELECT * FROM triage WHERE project_id=?", (job[0],))}
            for finding in payload.get("findings", []):
                finding["triage"] = reviews.get(finding["finding_id"], {"state": "open", "note": ""})
            return payload

    def review(self, uid, jid, fid, state, note):
        with self.connect() as db:
            job = self.job_access(db, uid, jid, "member")
            result = db.execute("SELECT payload FROM results WHERE job_id=?", (jid,)).fetchone()
            if not result or not any(f["finding_id"] == fid for f in json.loads(result[0]).get("findings", [])):
                raise AccessError()
            db.execute("INSERT OR REPLACE INTO triage VALUES(?,?,?,?,?,?)", (job["project_id"], fid, state, note, uid, time.time()))
            project = self.project_access(db, uid, job["project_id"])
            self.audit(db, uid, project["workspace_id"], "finding." + state, fid)
        return {"finding_id": fid, "state": state, "note": note}

    def audit_rows(self, uid, wid):
        with self.connect() as db:
            self.workspace_access(db, uid, wid, "admin")
            return [dict(r) for r in db.execute("SELECT * FROM audit WHERE workspace_id=? ORDER BY id DESC", (wid,))]

    def worker_access(self, db, pid, token):
        row = db.execute("SELECT * FROM projects WHERE id=? AND worker_token=?", (pid, digest(token))).fetchone()
        if not row:
            raise AccessError("Invalid worker credentials", 401)
        return row

    def claim(self, pid, token):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.worker_access(db, pid, token)
            db.execute("UPDATE projects SET worker_seen=? WHERE id=?", (time.time(), pid))
            self.expire_jobs(db)
            if db.execute("SELECT 1 FROM jobs WHERE project_id=? AND status='running'", (pid,)).fetchone():
                return None
            row = db.execute("SELECT * FROM jobs WHERE project_id=? AND status='queued' ORDER BY created LIMIT 1", (pid,)).fetchone()
            if not row:
                return None
            lease = secrets.token_urlsafe(32)
            db.execute("UPDATE jobs SET status='running',started=?,heartbeat=?,lease=? WHERE id=?",
                       (time.time(), time.time(), lease, row["id"]))
            return {**self.job_dict(row), "status": "running", "lease": lease}

    def leased_job(self, db, pid, token, jid, lease):
        self.worker_access(db, pid, token)
        row = db.execute("SELECT * FROM jobs WHERE id=? AND project_id=? AND status='running' AND lease=?",
                         (jid, pid, lease)).fetchone()
        if not row or row["heartbeat"] < time.time() - LEASE_SECONDS:
            raise AccessError("Worker lease is no longer valid", 409)
        return row

    def heartbeat(self, pid, token, jid, lease, progress):
        with self.connect() as db:
            row = self.leased_job(db, pid, token, jid, lease)
            db.execute("UPDATE jobs SET heartbeat=?,progress=? WHERE id=?", (time.time(), json.dumps(progress), jid))
            db.execute("UPDATE projects SET worker_seen=? WHERE id=?", (time.time(), pid))
            return {"cancel": bool(row["cancel"])}

    def complete(self, pid, token, jid, lease, payload, error):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.leased_job(db, pid, token, jid, lease)
            project = self.worker_access(db, pid, token)
            status = "cancelled" if row["cancel"] else ("failed" if error else "completed")
            if status == "completed":
                db.execute("INSERT INTO results VALUES(?,?)", (jid, json.dumps(payload)))
            db.execute("UPDATE jobs SET status=?,finished=?,error=? WHERE id=?", (status, time.time(), error, jid))
            self.audit(db, "worker:" + pid, project["workspace_id"], "job." + status, jid)
            return {"id": jid, "status": status}
