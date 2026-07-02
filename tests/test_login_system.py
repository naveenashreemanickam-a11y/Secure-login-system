import importlib.util
from pathlib import Path


def load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "users.db"))
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    module_path = Path(__file__).resolve().parents[1] / "login system.py"
    spec = importlib.util.spec_from_file_location("login_system_under_test", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.app.config.update(TESTING=True)
    return module


def fetch_password(module, username):
    with module.get_connection() as conn:
        row = conn.execute(
            "SELECT password FROM users WHERE username=?",
            (username,),
        ).fetchone()
    return row[0]


def test_register_stores_werkzeug_password_hash(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    client = module.app.test_client()

    response = client.post(
        "/register",
        data={"username": "alice", "password": "known-pass"},
    )

    assert response.status_code == 302
    stored_password = fetch_password(module, "alice")
    assert stored_password != "known-pass"
    assert not module.is_legacy_password_hash(stored_password)
    assert module.password_matches(stored_password, "known-pass")


def test_login_rehashes_legacy_sha256_password(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    with module.get_connection() as conn:
        conn.execute(
            "INSERT INTO users VALUES(?,?)",
            ("legacy", module.legacy_sha256("known-pass")),
        )
        conn.commit()

    client = module.app.test_client()
    response = client.post(
        "/login",
        data={"username": "legacy", "password": "known-pass"},
    )

    assert response.status_code == 302
    with client.session_transaction() as flask_session:
        assert flask_session["user"] == "legacy"

    stored_password = fetch_password(module, "legacy")
    assert not module.is_legacy_password_hash(stored_password)
    assert module.password_matches(stored_password, "known-pass")
