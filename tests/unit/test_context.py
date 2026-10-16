from pathlib import Path
from aisast.context.context_builder import ContextBuilder
from aisast.models import Candidate, Location
from aisast.verifier.prompts import render_prompt

def test_context_preserves_line_numbers_and_evidence_ids():
    root = Path("tests/fixtures/cwe89")
    candidate = Candidate(candidate_id="c", repository_sha="r", rule_id="sql", cwe=89, title="SQL", primary_location=Location(file="vulnerable.py", line=4), source=Location(file="vulnerable.py", line=2), sink=Location(file="vulnerable.py", line=4), path=[])
    packet = ContextBuilder(root).packet(candidate)
    assert packet.evidence
    assert any("query =" in e.code for e in packet.evidence)
    assert all(e.id.startswith("E") for e in packet.evidence)


def test_context_includes_subclass_override_for_inherited_sink(tmp_path: Path) -> None:
    (tmp_path / "viewer.py").write_text(
        "import os\n"
        "class Viewer:\n"
        "    def show_file(self, path):\n"
        "        os.system(self.get_command(path))\n"
        "class WindowsViewer(Viewer):\n"
        "    def get_command(self, file):\n"
        "        return 'start ' + file\n"
        "    def show_file(self, path):\n"
        "        os.startfile(path)\n"
    )
    candidate = Candidate(candidate_id="c", repository_sha="r", rule_id="cmd", cwe=78,
                          title="command", primary_location=Location(file="viewer.py", line=4),
                          source=Location(file="viewer.py", line=6),
                          sink=Location(file="viewer.py", line=4))
    packet = ContextBuilder(tmp_path).packet(candidate)
    assert any("class WindowsViewer(Viewer)" in block.code for block in packet.evidence)
    assert any("os.startfile(path)" in block.code for block in packet.evidence)


def test_long_function_keeps_alert_line_and_reports_truncation(tmp_path: Path) -> None:
    lines = ["def handler(value):"]
    lines.extend(f"    local_{index} = {index}" for index in range(1, 151))
    lines.append("    cursor.execute(value)")
    (tmp_path / "app.py").write_text("\n".join(lines) + "\n")
    alert_line = len(lines)
    candidate = Candidate(candidate_id="c", repository_sha="r", rule_id="sql", cwe=89,
                          title="SQL", primary_location=Location(file="app.py", line=alert_line),
                          sink=Location(file="app.py", line=alert_line))

    packet = ContextBuilder(tmp_path, max_chars=800).packet(candidate)
    prompt = render_prompt(packet, guided=False)

    assert any(block.start_line <= alert_line <= block.end_line
               and "cursor.execute(value)" in block.code for block in packet.evidence)
    assert packet.context_truncated
    assert any(block.truncated and block.source_end_line > block.end_line for block in packet.evidence)
    assert "ALERT LOCATION: app.py:" + str(alert_line) in prompt
    assert "PACKET CONTEXT TRUNCATED: true" in prompt
    assert "TRUNCATED:" in prompt


def test_context_includes_all_codeql_flow_locations(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def source():\n    value = input()\n    run(value)\n")
    candidate = Candidate(candidate_id="c", repository_sha="r", rule_id="command", cwe=78,
                          title="command", primary_location=Location(file="app.py", line=3),
                          sink=Location(file="app.py", line=3), properties={
                              "code_flows": [[
                                  {"file": "app.py", "line": 2},
                                  {"file": "app.py", "line": 3},
                              ], [
                                  {"file": "app.py", "line": 1},
                                  {"file": "app.py", "line": 3},
                              ]]
                          })

    packet = ContextBuilder(tmp_path).packet(candidate)
    prompt = render_prompt(packet, guided=False)

    assert any("input()" in block.code for block in packet.evidence)
    assert any("CODEQL POSSIBLE FLOW PATHS" in line for line in prompt.splitlines())
    assert "1. app.py:2 -> app.py:3" in prompt
    assert "2. app.py:1 -> app.py:3" in prompt


def test_pathless_alert_gets_labeled_bounded_local_value_clues(tmp_path: Path) -> None:
    lines = [
        "def handler(request, db):",
        "    user_value = request.args.get('name')",
        "    intermediate = user_value",
        "    query = 'SELECT * FROM users WHERE name=' + intermediate",
    ]
    lines.extend(f"    unused_{index} = {index}" for index in range(90))
    lines.append("    db.execute(query)")
    (tmp_path / "app.py").write_text("\n".join(lines) + "\n")
    alert_line = len(lines)
    candidate = Candidate(candidate_id="c", repository_sha="r", rule_id="sql", cwe=89,
                          title="SQL", primary_location=Location(file="app.py", line=alert_line),
                          sink=Location(file="app.py", line=alert_line))

    packet = ContextBuilder(tmp_path, max_chars=1200).packet(candidate)
    prompt = render_prompt(packet, guided=False)

    slices = [block for block in packet.evidence if block.kind == "slice"]
    assert len(slices) <= 6
    assert any("query =" in block.code for block in slices)
    assert any("user_value =" in block.code for block in slices)
    assert "syntactic candidates, not proven flow edges" in prompt
