"""Product API, authorization, job lifecycle and incremental regression checks."""
import pytest

pytest.importorskip("fastapi", reason="Product tests require the web extra")
from fastapi.testclient import TestClient

from aisast.product.api import create_app
from aisast.product.cli import workspace_choice
from aisast.product.incremental import inventory, plan, snapshot
from aisast.product.store import AccessError, Store


@pytest.fixture
def installation(tmp_path):
    store = Store(tmp_path / "server")
    boot = store.bootstrap("admin", "test-only-password-123", "Team A")
    session = store.login("admin", "test-only-password-123")
    uid = store.user(session["token"])["id"]
    pid = store.create_project(uid, boot["workspace_id"], "small")["id"]
    return store, uid, boot["workspace_id"], pid, session["token"]


def test_workspace_numeric_name_and_id_selection(monkeypatch):
    class API:
        def request(self, *args):
            return [{"id": "aaa", "name": "First", "role": "admin"},
                    {"id": "bbb", "name": "Second", "role": "admin"}]
    monkeypatch.setattr("builtins.input", lambda _: "2")
    assert workspace_choice(API()) == "bbb"
    assert workspace_choice(API(), "Second") == "bbb"
    assert workspace_choice(API(), "aaa") == "aaa"
    with pytest.raises(RuntimeError):
        workspace_choice(API(), "3")


def test_workspace_and_role_isolation(installation):
    store, uid, wid, pid, _ = installation
    other = store.create_workspace(uid, "Team B")["id"]
    store.set_member(uid, other, "outsider", "member", "test-only-password-123")
    store.set_member(uid, wid, "viewer", "viewer", "test-only-password-123")
    outsider = store.user(store.login("outsider", "test-only-password-123")["token"])["id"]
    viewer = store.user(store.login("viewer", "test-only-password-123")["token"])["id"]
    assert store.projects(outsider) == []
    with pytest.raises(AccessError) as error:
        store.jobs(outsider, pid)
    assert error.value.status == 404
    with pytest.raises(AccessError) as error:
        store.enqueue(viewer, pid, False)
    assert error.value.status == 403
    with pytest.raises(AccessError) as error:
        store.set_member(uid, wid, "admin", "viewer")
    assert error.value.status == 409


def test_queue_worker_lease_and_rotation(installation):
    store, uid, _, pid, _ = installation
    token = store.rotate_worker(uid, pid)["token"]
    job = store.enqueue(uid, pid, True)
    with pytest.raises(AccessError):
        store.enqueue(uid, pid, False)
    claim = store.claim(pid, token)
    assert claim["id"] == job["id"]
    assert store.claim(pid, token) is None
    with pytest.raises(AccessError):
        store.heartbeat(pid, token, job["id"], "incorrect", {})
    assert not store.heartbeat(pid, token, job["id"], claim["lease"], {})["cancel"]
    store.cancel(uid, job["id"])
    assert store.heartbeat(pid, token, job["id"], claim["lease"], {})["cancel"]
    assert store.complete(pid, token, job["id"], claim["lease"], {}, "cancel")["status"] == "cancelled"
    store.rotate_worker(uid, pid)
    with pytest.raises(AccessError) as error:
        store.claim(pid, token)
    assert error.value.status == 401


def test_expired_lease_fails_and_cannot_publish(installation):
    store, uid, _, pid, _ = installation
    token = store.rotate_worker(uid, pid)["token"]
    job = store.enqueue(uid, pid, False)
    claim = store.claim(pid, token)
    with store.connect() as db:
        db.execute("UPDATE jobs SET heartbeat=0 WHERE id=?", (job["id"],))
    assert store.job(uid, job["id"])["status"] == "failed"
    with pytest.raises(AccessError):
        store.complete(pid, token, job["id"], claim["lease"], {}, None)


def test_finding_review_persists_without_changing_verdict(installation):
    store, uid, _, pid, token = installation
    worker = store.rotate_worker(uid, pid)["token"]
    job = store.enqueue(uid, pid, True)
    claim = store.claim(pid, worker)
    payload = {"summary": {}, "findings": [{"finding_id": "finding-one", "verdict": "VULNERABLE"}]}
    store.complete(pid, worker, job["id"], claim["lease"], payload, None)
    assert store.review(uid, job["id"], "finding-one", "confirmed", "Source checked")["state"] == "confirmed"
    finding = store.result(uid, job["id"])["findings"][0]
    assert finding["verdict"] == "VULNERABLE"
    assert finding["triage"]["note"] == "Source checked"
    store.review(uid, job["id"], "finding-one", "dismissed", "Updated review")
    assert store.result(uid, job["id"])["findings"][0]["triage"]["state"] == "dismissed"
    assert any(row["action"] == "finding.dismissed" for row in store.audit_rows(uid, store.projects(uid)[0]["workspace_id"]))


def test_password_change_revokes_all_sessions(installation):
    store, uid, _, _, token = installation
    second = store.login("admin", "test-only-password-123")["token"]
    store.change_password(uid, "test-only-password-123", "new-test-password-123")
    for old in (token, second):
        with pytest.raises(AccessError):
            store.user(old)
    assert store.login("admin", "new-test-password-123")


def test_browser_cookie_csrf_host_and_logout(tmp_path):
    store = Store(tmp_path / "server")
    store.bootstrap("admin", "test-only-password-123", "Team")
    app = create_app(tmp_path / "server", "http://testserver", ["http://100.111.217.22:8765"])
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/assets/app.js").status_code == 200
        assert client.get("/api/projects").status_code == 401
        assert client.get("/api/health", headers={"Host": "bad.example"}).status_code == 400
        assert client.get("/api/health", headers={"Host": "100.111.217.22:8765"}).status_code == 200
        browser = {"Origin": "http://testserver", "X-OpenSAST-CSRF": "1"}
        response = client.post("/api/login", json={"username": "admin", "password": "test-only-password-123"}, headers=browser)
        assert response.status_code == 200
        assert "token" not in response.json()
        assert "httponly" in response.headers["set-cookie"].lower()
        assert client.get("/api/me").status_code == 200
        assert client.post("/api/workspaces", json={"name": "Bad"}, headers={"Origin": "http://testserver"}).status_code == 403
        assert client.post("/api/workspaces", json={"name": "Bad"}, headers={**browser, "Origin": "http://bad.example"}).status_code == 403
        assert client.post("/api/logout", headers=browser).status_code == 200
        assert client.get("/api/me").status_code == 401


def test_login_throttling(tmp_path):
    app = create_app(tmp_path / "server", "http://testserver")
    with TestClient(app) as client:
        for _ in range(5):
            assert client.post("/api/login", json={"username": "unknown", "password": "bad"}).status_code == 401
        assert client.post("/api/login", json={"username": "unknown", "password": "bad"}).status_code == 429


def test_incremental_reverse_imports_and_deletions():
    previous = {"files": {"a.py": "old", "b.py": "same"}, "graph": {"b.py": ["a.py"]}}
    changed = plan({"a.py": "new", "b.py": "same"}, previous, {"b.py": ["a.py"]}, [])
    assert changed["mode"] == "incremental"
    assert changed["affected_files"] == ["a.py", "b.py"]
    removed = plan({"b.py": "same"}, previous, {"b.py": []}, [])
    assert removed["affected_files"] == ["a.py", "b.py"]
    assert not plan(previous["files"], previous, previous["graph"], [])["changed_files"]


@pytest.mark.parametrize("changed", ["requirements.txt", "templates/page.html"])
def test_non_python_change_forces_full(changed):
    previous = {"files": {"a.py": "same", changed: "old"}, "graph": {}}
    result = plan({"a.py": "same", changed: "new"}, previous, {}, [])
    assert result["mode"] == "full"
    assert "a.py" in result["affected_files"]


def test_snapshot_excludes_local_state_and_links(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("print('small')\n")
    (root / ".opensast").mkdir()
    (root / ".opensast" / "config.json").write_text("{}")
    (root / "link.py").symlink_to(root / "a.py")
    files = inventory(root)
    assert set(files) == {"a.py"}
    destination = tmp_path / "snapshot"
    snapshot(root, destination, files)
    assert inventory(destination) == files
