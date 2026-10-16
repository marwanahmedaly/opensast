from pathlib import Path

from aisast.codeql.runner import CodeQLRunner


def test_codeql_scan_creates_workdir_and_splits_pack_search_path(tmp_path: Path):
    calls: list[list[str]] = []

    class FakeRunner(CodeQLRunner):
        def _run(self, args: list[str]) -> None:
            calls.append(args)

    output = FakeRunner("codeql").scan(
        tmp_path / "repo",
        tmp_path / "nested" / "raw",
        "codeql/python-queries:codeql-suites/python-security-extended.qls",
        search_path=Path("/packs/queries:/packs/libraries"),
    )

    assert output == tmp_path / "nested" / "raw" / "codeql.sarif"
    assert (tmp_path / "nested" / "raw").is_dir()
    assert calls[0][0:2] == ["database", "create"]
    assert "--search-path=/packs/queries:/packs/libraries" in calls[1]
    assert "--additional-packs=/packs/queries" not in calls[1]
    assert "--additional-packs=/packs/libraries" not in calls[1]
    assert "--rerun" in calls[1]


def test_model_ablation_forces_fresh_query_and_can_ignore_database_extensions(tmp_path):
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "qlpack.yml").write_text(
        "name: aisast/test-models\nversion: 0.0.1\nlibrary: true\n",
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    class FakeRunner(CodeQLRunner):
        def _run(self, args: list[str]) -> None:
            calls.append(args)

    FakeRunner("codeql").analyze(
        tmp_path / "db", tmp_path / "out.sarif", search_path=tmp_path / "packs",
        model_packs=[pack], no_database_extension_packs=True,
    )
    assert "--rerun" in calls[0]
    assert "--no-database-extension-packs" in calls[0]
    assert "--model-packs=aisast/test-models" in calls[0]
    assert f"--additional-packs={tmp_path}" in calls[0]
