import json
from pathlib import Path
from aisast.codeql.sarif import write_sarif
from aisast.models import FinalFinding, Location, Verdict

def test_final_findings_can_be_exported_as_sarif(tmp_path: Path):
    finding = FinalFinding(candidate_id="c", cwe=89, rule_id="sql", verdict=Verdict.VULNERABLE, location=Location(file="x.py", line=3), evidence_ids=["E1"], explanation="bound")
    output = tmp_path / "out.sarif"; write_sarif([finding], output)
    data = json.loads(output.read_text())
    assert data["runs"][0]["results"][0]["properties"]["candidate_id"] == "c"
