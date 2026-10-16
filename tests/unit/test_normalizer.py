from aisast.codeql.normalizer import normalize_sarif

def test_normalizer_is_deterministic_and_extracts_path():
    sarif = {"runs": [{"tool": {"driver": {"rules": [{"id": "py/sql-injection", "properties": {"tags": ["cwe-89"]}}]}}, "results": [{"ruleId": "py/sql-injection", "message": {"text": "SQL injection"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 8}}}], "codeFlows": [{"threadFlows": [{"locations": [{"location": {"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 2}}}}, {"location": {"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 8}}}}]}]}]}] }]}
    first = normalize_sarif(sarif, "abc"); second = normalize_sarif(sarif, "abc")
    assert first[0].candidate_id == second[0].candidate_id
    assert first[0].cwe == 89 and first[0].source.line == 2 and first[0].sink.line == 8


def test_normalizer_resolves_cwd_relative_sarif_uri_to_repository(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = tmp_path / "benchmarks" / "repos" / "sample"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text("cursor.execute(query)\n")
    sarif = {"runs": [{"tool": {"driver": {"rules": [{"id": "py/sql-injection", "properties": {"tags": ["cwe-89"]}}]}}, "results": [{"ruleId": "py/sql-injection", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "benchmarks/repos/sample/app.py"}, "region": {"startLine": 1}}}]}]}]}

    candidate = normalize_sarif(sarif, source_root=repo, engine="semgrep")[0]

    assert candidate.primary_location.file == "app.py"
    assert (repo / candidate.primary_location.file).exists()

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    replayed = normalize_sarif(sarif, source_root=repo, engine="semgrep")[0]
    assert replayed.primary_location.file == "app.py"


def test_normalizer_keeps_alternative_code_flows_separate():
    sarif = {"runs": [{"tool": {"driver": {"rules": [{"id": "py/sql-injection", "properties": {"tags": ["cwe-89"]}}]}}, "results": [{
        "ruleId": "py/sql-injection",
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 8}}}],
        "codeFlows": [{"threadFlows": [
            {"locations": [
                {"location": {"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 2}}}},
                {"location": {"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 8}}}},
            ]},
            {"locations": [
                {"location": {"physicalLocation": {"artifactLocation": {"uri": "other.py"}, "region": {"startLine": 4}}}},
                {"location": {"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 8}}}},
            ]},
        ]}]
    }]}]}

    candidate = normalize_sarif(sarif, "abc")[0]

    assert [location.line for location in candidate.path] == [2, 8]
    assert candidate.source.file == "app.py" and candidate.sink.line == 8
    assert [[(item["file"], item["line"]) for item in flow]
            for flow in candidate.properties["code_flows"]] == [
                [("app.py", 2), ("app.py", 8)],
                [("other.py", 4), ("app.py", 8)],
            ]
