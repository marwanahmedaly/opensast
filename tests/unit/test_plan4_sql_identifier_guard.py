from pathlib import Path

from aisast.plan4.sql_identifier_guard import prove_quoted_sqlite_identifier


def test_sqlite_double_quoted_identifier_is_guarded(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import sqlite3\n"
        "def inspect(database):\n"
        "    cur = sqlite3.connect(database).cursor()\n"
        "    name = cur.fetchall()[0][0]\n"
        "    escaped = name.replace('\"', '\"\"')\n"
        "    cur.execute(f'SELECT * FROM \"{escaped}\"')\n")
    assert prove_quoted_sqlite_identifier(tmp_path, "app.py", 6)["sanitizer_lines"] == [5]


def test_unquoted_or_wrong_escape_is_not_guarded(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import sqlite3\n"
        "def inspect(database):\n"
        "    cur = sqlite3.connect(database).cursor()\n"
        "    name = cur.fetchall()[0][0]\n"
        "    escaped = name.replace('\"', '\"\"')\n"
        "    cur.execute(f'SELECT * FROM {escaped}')\n"
        "    cur.execute(f'SELECT * FROM \"{name}\"')\n")
    assert prove_quoted_sqlite_identifier(tmp_path, "app.py", 6) is None
    assert prove_quoted_sqlite_identifier(tmp_path, "app.py", 7) is None


def test_unrelated_cursor_and_format_conversion_are_not_guarded(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import sqlite3\n"
        "def inspect(database, other_cursor):\n"
        "    cur = sqlite3.connect(database).cursor()\n"
        "    name = cur.fetchall()[0][0]\n"
        "    escaped = name.replace('\"', '\"\"')\n"
        "    other_cursor.execute(f'SELECT * FROM \"{escaped}\"')\n"
        "    cur.execute(f'SELECT * FROM \"{escaped!r}\"')\n")
    assert prove_quoted_sqlite_identifier(tmp_path, "app.py", 6) is None
    assert prove_quoted_sqlite_identifier(tmp_path, "app.py", 7) is None


def test_mobsf_paired_patch(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    pair = root / "benchmarks/plan4-end-to-end/repos/CVE-2026-33545"
    vulnerable = pair / "vulnerable"
    patched = pair / "patched"
    file = "mobsf/MobSF/utils.py"
    assert prove_quoted_sqlite_identifier(vulnerable, file, 553) is None
    assert prove_quoted_sqlite_identifier(vulnerable, file, 557) is None
    assert prove_quoted_sqlite_identifier(patched, file, 556) is not None
    assert prove_quoted_sqlite_identifier(patched, file, 560) is not None
