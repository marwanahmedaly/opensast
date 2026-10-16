from __future__ import annotations

from enum import StrEnum
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class Verdict(StrEnum):
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    NEEDS_MORE_CONTEXT = "NEEDS_MORE_CONTEXT"
    SYSTEM_ERROR = "SYSTEM_ERROR"
    UNRESOLVED = "UNRESOLVED"


class Location(BaseModel):
    file: str
    line: int = Field(ge=1)
    column: int | None = Field(default=None, ge=1)


class EvidenceBlock(BaseModel):
    id: str
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    code: str
    kind: Literal["source", "sink", "path", "context", "expansion", "slice", "relation"] = "context"
    truncated: bool = False
    source_end_line: int | None = None


class Candidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_id: str
    repository_sha: str
    rule_id: str
    cwe: int
    title: str
    message: str = ""
    primary_location: Location
    source: Location | None = None
    sink: Location | None = None
    path: list[Location] = Field(default_factory=list)
    properties: dict[str, object] = Field(default_factory=dict)
    # Fusion metadata is populated after independent scanner runs.  Keeping it
    # on the normalized candidate makes raw rule provenance available to both
    # the verifier and the evaluation reports.
    engines: list[str] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)


class EvidencePacket(BaseModel):
    candidate: Candidate
    evidence: list[EvidenceBlock]
    profile: str
    prompt_version: str
    context_truncated: bool = False
    incomplete_evidence_blocks: int = 0
    context_resolution: list[dict[str, object]] = Field(default_factory=list)
    framework_facts: list[str] = Field(default_factory=list)


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_id: str
    cwe: int | None = None
    verdict: Verdict
    source_evidence: list[str] = Field(default_factory=list)
    sink_evidence: list[str] = Field(default_factory=list)
    sanitizer_evidence: list[str] = Field(default_factory=list)
    explanation: str = ""
    missing_symbols: list[str] = Field(default_factory=list)


class FinalFinding(BaseModel):
    candidate_id: str
    cwe: int
    rule_id: str
    verdict: Verdict
    location: Location
    evidence_ids: list[str] = Field(default_factory=list)
    explanation: str = ""
    validation_errors: list[str] = Field(default_factory=list)


class RunManifest(BaseModel):
    run_id: str
    repository: str
    repository_sha: str
    scanner_version: str
    python_version: str
    codeql_version: str | None = None
    query_pack_version: str | None = None
    model: str | None = None
    quantization: str | None = None
    context_length: int = 10240
    temperature: float = 0.0
    top_p: float = 1.0
    prompt_hash: str
    config_hash: str
    created_at: str
    scanners: list[str] = Field(default_factory=list)
    scanner_versions: dict[str, str] = Field(default_factory=dict)
    dataset_commit: str | None = None
    backend: str | None = None
    model_sha256: str | None = None
    candidate_sha256: str | None = None
    max_tokens: int | None = None
    max_retries: int | None = None
    rule_profile: str | None = None
    rule_profile_sha256: str | None = None
    guided_questions_sha256: str | None = None
    source_run_sha256: str | None = None
