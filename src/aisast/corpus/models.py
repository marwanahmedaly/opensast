"""Versioned data contracts for Plan 7 corpus artifacts."""
from __future__ import annotations

import re
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

SCHEMA_VERSION = "1.0"
SUPPORTED_CWES = (22, 78, 79, 89)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)
    schema_version: str = SCHEMA_VERSION


class CaseState(StrEnum):
    DISCOVERED = "discovered"
    TRIAGED = "triaged"
    REPO_RESOLVED = "repo_resolved"
    REVISIONS_PINNED = "revisions_pinned"
    ANNOTATION_PENDING = "annotation_pending"
    ANNOTATED = "annotated"
    GOLD = "gold"
    EXCLUDED = "excluded"
    UNRESOLVED = "unresolved"


class ExclusionReason(StrEnum):
    NOT_TARGET_CWE = "not_target_cwe"
    NOT_PYTHON_IMPLEMENTATION = "not_python_implementation"
    NOT_FULL_REPO = "not_full_repo"
    NO_PUBLIC_VULNERABLE_REVISION = "no_public_vulnerable_revision"
    CLAIM_WITHDRAWN = "claim_withdrawn"
    DUPLICATE = "duplicate"
    WRONG_UPSTREAM_REPO = "wrong_upstream_repo"
    LICENSE_OR_ACCESS_BLOCK = "license_or_access_block"
    UNSUBSTANTIATED_CLAIM = "unsubstantiated_claim"
    DATASET_RECORD_INVALID = "dataset_record_invalid"


class QueryScope(StrEnum):
    PYTHON_BINDABLE = "python_bindable"
    OUTSIDE_PYTHON_QUERY = "outside_python_query"
    UNKNOWN = "unknown"


class PairStatus(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    UNRESOLVED = "unresolved"
    NOT_APPLICABLE = "not_applicable"


class FixedSiteMappingStatus(StrEnum):
    NOT_MAPPED = "not_mapped"
    MAPPED = "mapped"
    NOT_MAPPABLE = "not_mappable"
    NO_FIXED_REVISION = "no_fixed_revision"


class EndpointKind(StrEnum):
    REQUEST_ARGUMENT = "request_argument"
    FUNCTION_PARAMETER = "function_parameter"
    FIELD_READ = "field_read"
    CALL_RESULT = "call_result"
    FILE_CONTENT = "file_content"
    FILESYSTEM = "filesystem"
    PROCESS = "process"
    HTML = "html"
    TEMPLATE = "template"
    JAVASCRIPT = "javascript"
    SQL = "sql"
    OTHER = "other"


class EndpointRole(StrEnum):
    TRUST_BOUNDARY = "trust_boundary"
    DERIVED_PROXY = "derived_proxy"


class LanguageBoundary(StrEnum):
    PYTHON_ONLY = "python_only"
    PYTHON_TO_TEMPLATE = "python_to_template"
    PYTHON_TO_JAVASCRIPT = "python_to_javascript"
    OTHER = "other"
    UNKNOWN = "unknown"


class ReviewEvidenceKind(StrEnum):
    CLAIM = "claim"
    SOURCE_CONTROL = "source_control"
    SINK_SEMANTICS = "sink_semantics"
    DATAFLOW_STEP = "dataflow_step"
    GUARD = "guard"
    FIX = "fix"
    CONFIGURATION = "configuration"
    TEST = "test"
    OTHER = "other"


class RawArtifactKind(StrEnum):
    HTTP_RESPONSE = "http_response"
    BULK_ARCHIVE = "bulk_archive"
    DELTA_RECORD = "delta_record"
    REPOSITORY_FILE = "repository_file"
    DATASET_LABEL_FILE = "dataset_label_file"
    LEGACY_PAGE_REPRESENTATION = "legacy_page_representation"


class ReviewEvidence(StrictModel):
    """One traceable evidence item used by a reviewer annotation."""

    evidence_id: str
    kind: ReviewEvidenceKind
    revision_role: str | None = None
    revision_tree_sha: str | None = None
    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    file_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    excerpt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    excerpt: str | None = None
    source_url: str | None = None
    source_record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    explanation: str

    @model_validator(mode="after")
    def check_evidence_location(self) -> "ReviewEvidence":
        if not self.file and not self.source_url:
            raise ValueError("review evidence needs a repository file or source URL")
        if self.file:
            if not self.line or not self.file_sha256 or not self.excerpt_sha256:
                raise ValueError("repository evidence needs line, file hash, and excerpt hash")
            if self.start_line and self.end_line and self.start_line > self.end_line:
                raise ValueError("evidence start_line cannot follow end_line")
        if self.excerpt is not None and self.excerpt_sha256:
            import hashlib

            actual = hashlib.sha256(self.excerpt.encode("utf-8")).hexdigest()
            if actual != self.excerpt_sha256:
                raise ValueError("excerpt_sha256 does not match excerpt text")
        return self


class RawArtifactRef(StrictModel):
    """Pointer from a normalized discovery back to immutable acquired bytes."""

    artifact_uri: str
    artifact_kind: RawArtifactKind
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_locator: dict[str, Any]
    request_id: str | None = None
    source_revision: str | None = None
    parent_snapshot_id: str | None = None


class EndpointSite(StrictModel):
    kind: EndpointKind
    role: EndpointRole | None = None
    symbol: str | None = None
    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    file_sha256: str | None = None
    position: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    codeql_binding_status: str | None = None


class EvidenceEdge(StrictModel):
    evidence_id: str
    edge_kind: str
    from_node: dict[str, Any]
    to_node: dict[str, Any]
    file: str | None = None
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    file_sha256: str | None = None
    excerpt_sha256: str | None = None
    explanation: str
    confidence: float | None = Field(default=None, ge=0, le=1)


class Discovery(StrictModel):
    discovery_id: str
    source_name: str
    source_record_id: str
    source_record_version: str | None = None
    source_url: HttpUrl | str
    retrieved_at: str
    raw_record_sha256: str
    source_record_content_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    raw_artifact_refs: list[RawArtifactRef] = Field(default_factory=list)
    original_aliases: list[str] = Field(default_factory=list)
    original_cwes: list[str] = Field(default_factory=list)
    normalized_cwes: list[int] = Field(default_factory=list)
    package_names: list[str] = Field(default_factory=list)
    ecosystems: list[str] = Field(default_factory=list)
    repository_urls: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    affected_ranges: list[dict[str, Any]] = Field(default_factory=list)
    withdrawn: bool = False
    reviewed_state: str | None = None
    summary: str | None = None
    description: str | None = None
    provenance_class: str = "real_disclosed"
    dataset_expected_vulnerable: bool | None = None
    dataset_category: str | None = None
    dataset_version: str | None = None
    status: str = "queued"
    exclusion_reason: ExclusionReason | None = None
    unresolved_reason: str | None = None
    merged_into: str | None = None
    split_from: str | None = None


class Case(StrictModel):
    case_id: str
    aliases: list[str] = Field(default_factory=list)
    source_discovery_ids: list[str] = Field(default_factory=list)
    upstream_repository_id: str | None = None
    repository_url: str | None = None
    package_names: list[str] = Field(default_factory=list)
    original_cwes: list[str] = Field(default_factory=list)
    source_claimed_cwes: list[int] = Field(default_factory=list)
    reviewed_cwes: list[int] = Field(default_factory=list)
    cwe_mapping_rationale: str | None = None
    provenance_class: str = "real_disclosed"
    benchmark_expected_vulnerable: bool | None = None
    benchmark_categories: list[str] = Field(default_factory=list)
    claim_status: str = "unreviewed"
    state: CaseState = CaseState.DISCOVERED
    exclusion_reason: ExclusionReason | None = None
    unresolved_reason: str | None = None
    attacker_capability: str | None = None
    affected_versions: list[dict[str, Any]] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    vulnerable_behavior: str | None = None
    fixed_behavior: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    variant_ids: list[str] = Field(default_factory=list)
    split: str = "unassigned"
    history: list[dict[str, Any]] = Field(default_factory=list)


class Revision(StrictModel):
    revision_id: str
    case_id: str
    variant_id: str
    role: str
    repository_url: str
    commit_sha: str | None = None
    tree_sha: str | None = None
    ref: str | None = None
    version: str | None = None
    cache_path: str | None = None
    checkout_recipe: list[str] = Field(default_factory=list)
    source_archive_url: str | None = None
    source_archive_sha256: str | None = None
    relevant_file_hashes: dict[str, str] = Field(default_factory=dict)
    relation_evidence_ids: list[str] = Field(default_factory=list)
    reviewer_id: str | None = None
    review_id: str | None = None
    mapping_rationale: str | None = None
    no_fixed_reason: str | None = None
    status: str = "unresolved"
    status_reason: str | None = None
    acquired_at: str | None = None


class EndpointPair(StrictModel):
    pair_id: str
    case_id: str
    variant_id: str
    vulnerable_tree_sha: str
    fixed_tree_sha: str | None = None
    cwe: int
    condition: dict[str, Any] = Field(default_factory=dict)
    source: EndpointSite | None = None
    sink: EndpointSite | None = None
    fixed_source: EndpointSite | None = None
    fixed_sink: EndpointSite | None = None
    fixed_site_mapping_status: FixedSiteMappingStatus = FixedSiteMappingStatus.NOT_MAPPED
    fixed_site_mapping_rationale: str | None = None
    steps: list[EvidenceEdge] = Field(default_factory=list)
    guards: list[EvidenceEdge] = Field(default_factory=list)
    fix_explanation: str | None = None
    no_fix_reason: str | None = None
    pair_status: PairStatus = PairStatus.UNRESOLVED
    query_scope: QueryScope = QueryScope.UNKNOWN
    language_boundary: LanguageBoundary = LanguageBoundary.UNKNOWN
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    missing_endpoint: str | None = None
    not_applicable_explanation: str | None = None
    review_ids: list[str] = Field(default_factory=list)
    annotation_version: int = Field(default=1, ge=1)
    history: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_pair_semantics(self) -> "EndpointPair":
        if self.pair_status == PairStatus.CONFIRMED:
            if self.source is None or self.sink is None:
                raise ValueError("confirmed pairs require exact source and sink sites")
            for site in (self.source, self.sink):
                if not site.file or not site.line or not site.column:
                    raise ValueError("confirmed pairs require exact source/sink file, line, and column")
                if not site.file_sha256 or not site.evidence_ids:
                    raise ValueError("confirmed pairs require source/sink file hashes and evidence references")
            if self.missing_endpoint:
                raise ValueError("confirmed pair cannot retain missing_endpoint")
            if not self.supporting_evidence_ids:
                raise ValueError("confirmed pair requires supporting evidence references")
        if self.pair_status == PairStatus.NOT_APPLICABLE:
            if self.source is not None or self.sink is not None:
                raise ValueError("not_applicable pairs cannot claim a taint source or sink")
            if not self.not_applicable_explanation:
                raise ValueError("not_applicable requires its actual flaw mechanism")
            if not self.supporting_evidence_ids:
                raise ValueError("not_applicable requires supporting evidence references")
        if self.pair_status == PairStatus.UNRESOLVED and self.source is None and self.sink is None:
            if not self.missing_endpoint:
                raise ValueError("empty unresolved pair must explain the missing endpoint")
        if self.pair_status == PairStatus.PROBABLE and self.source is None and self.sink is None:
            if not self.missing_endpoint:
                raise ValueError("empty probable pair must explain its missing endpoint")
        if self.fixed_site_mapping_status == "mapped":
            if not self.fixed_tree_sha or self.fixed_source is None or self.fixed_sink is None:
                raise ValueError("mapped fixed endpoints require fixed tree, source, and sink")
            for site in (self.fixed_source, self.fixed_sink):
                if not site.file or not site.line or not site.column:
                    raise ValueError("mapped fixed endpoints require exact file, line, and column")
                if not site.file_sha256 or not site.evidence_ids:
                    raise ValueError("mapped fixed endpoints require file hashes and evidence references")
        if (self.fixed_source is not None or self.fixed_sink is not None) and self.fixed_site_mapping_status != "mapped":
            raise ValueError("fixed source/sink sites require fixed_site_mapping_status=mapped")
        if self.fixed_site_mapping_status == "no_fixed_revision" and not self.no_fix_reason:
            raise ValueError("no_fixed_revision mapping status requires no_fix_reason")
        return self


class ModelOpportunityKind(StrEnum):
    REUSABLE_EXTERNAL_API = "reusable_external_api"
    REUSABLE_STRUCTURAL_PATTERN = "reusable_structural_pattern"
    ALREADY_STOCK_MODELED = "already_stock_modeled"
    CASE_ONLY = "case_only"
    OUTSIDE_PYTHON_QUERY = "outside_python_query"
    UNKNOWN = "unknown"


class ModelRole(StrEnum):
    SOURCE = "source"
    SINK = "sink"
    SUMMARY = "summary"
    BARRIER = "barrier"
    BARRIER_GUARD = "barrier_guard"


class ModelRepresentation(StrEnum):
    DATA_EXTENSION = "data_extension"
    QL_LIBRARY = "ql_library"


class ModelDecisionState(StrEnum):
    NEEDS_EVIDENCE = "needs_evidence"
    REJECTED = "rejected"
    APPROVED_FOR_VALIDATION = "approved_for_validation"
    ACCEPTED = "accepted"
    REVISED = "revised"


class AgentModelOpportunity(StrictModel):
    """Agent's explicit decision about whether an inspected endpoint generalizes."""

    opportunity_id: str
    kind: ModelOpportunityKind
    role: ModelRole | None = None
    cwe: int
    semantic_scope: str
    semantic_contract: str
    representation: ModelRepresentation = ModelRepresentation.DATA_EXTENSION
    codeql_type: str | None = None
    codeql_path: str | None = None
    codeql_kind: str | None = None
    codeql_tuple: list[str] = Field(default_factory=list)
    ql_source_path: str | None = None
    ql_source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    ql_symbol: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    api_documentation_urls: list[str] = Field(default_factory=list)
    stock_model_status: str = "not_checked"
    expected_node: str | None = None
    rationale: str

    @model_validator(mode="after")
    def check_model_opportunity(self) -> "AgentModelOpportunity":
        if self.cwe not in SUPPORTED_CWES:
            raise ValueError(f"unsupported Plan 7 CWE: {self.cwe}")
        reusable = self.kind in {
            ModelOpportunityKind.REUSABLE_EXTERNAL_API,
            ModelOpportunityKind.REUSABLE_STRUCTURAL_PATTERN,
        }
        if reusable:
            if not all((self.role, self.codeql_kind, self.semantic_scope.strip(),
                        self.semantic_contract.strip())):
                raise ValueError("reusable model opportunities need role, kind, and semantic contract")
            if self.representation == ModelRepresentation.DATA_EXTENSION:
                if not all((self.codeql_type, self.codeql_path, self.codeql_tuple)):
                    raise ValueError("data-extension opportunities require an explicit CodeQL tuple")
                if any((self.ql_source_path, self.ql_source_sha256, self.ql_symbol)):
                    raise ValueError("data-extension opportunities cannot carry a QL library")
            else:
                if self.kind != ModelOpportunityKind.REUSABLE_STRUCTURAL_PATTERN:
                    raise ValueError("QL library opportunities must describe a reusable structural pattern")
                if not all((self.ql_source_path, self.ql_source_sha256, self.ql_symbol)):
                    raise ValueError("QL library opportunities need a hashed source file and symbol")
                if any((self.codeql_type, self.codeql_path, self.codeql_tuple)):
                    raise ValueError("QL library opportunities cannot carry a data-extension tuple")
            if not self.evidence_ids:
                raise ValueError("reusable model opportunities require evidence references")
            if self.stock_model_status not in {"present", "absent"}:
                raise ValueError("check the stock model before proposing a reusable model")
        elif any((self.codeql_tuple, self.codeql_type, self.codeql_path,
                  self.ql_source_path, self.ql_source_sha256, self.ql_symbol)):
            raise ValueError("non-reusable opportunities cannot carry production CodeQL models")
        return self


class AgentEndpointCard(StrictModel):
    """Agent-authored inspection of one labeled, pinned vulnerable variant."""

    card_id: str
    card_version: int = Field(default=1, ge=1)
    supersedes_card_id: str | None = None
    case_id: str
    variant_id: str
    cwe: int
    provenance_class: str
    upstream_project_family: str
    vulnerable_tree_sha: str
    fixed_tree_sha: str | None = None
    agent_id: str
    action_ids: list[str] = Field(default_factory=list)
    created_at: str
    attacker_capability: str
    attacker_preconditions: list[str] = Field(default_factory=list)
    vulnerability_hypothesis: str
    pair_status: PairStatus
    endpoint_pairs: list[EndpointPair] = Field(default_factory=list)
    not_applicable_explanation: str | None = None
    evidence: list[ReviewEvidence] = Field(default_factory=list)
    model_opportunities: list[AgentModelOpportunity] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_card(self) -> "AgentEndpointCard":
        if self.cwe not in SUPPORTED_CWES:
            raise ValueError(f"unsupported Plan 7 CWE: {self.cwe}")
        if self.card_version > 1 and not self.supersedes_card_id:
            raise ValueError("revised agent cards must identify the superseded card")
        if self.pair_status == PairStatus.CONFIRMED and not self.endpoint_pairs:
            raise ValueError("confirmed agent card requires at least one endpoint pair")
        if self.pair_status == PairStatus.NOT_APPLICABLE and not self.not_applicable_explanation:
            raise ValueError("not_applicable agent card needs the non-taint mechanism")
        if self.pair_status == PairStatus.UNRESOLVED and not self.unresolved_questions:
            raise ValueError("unresolved agent card must list what is missing")
        evidence_ids = {row.evidence_id for row in self.evidence}
        for pair in self.endpoint_pairs:
            if pair.case_id != self.case_id or pair.variant_id != self.variant_id:
                raise ValueError("endpoint pair belongs to another case or variant")
            if pair.cwe != self.cwe or pair.vulnerable_tree_sha != self.vulnerable_tree_sha:
                raise ValueError("endpoint pair CWE/tree does not match its agent card")
            cited = set(pair.supporting_evidence_ids)
            for site in (pair.source, pair.sink):
                if site:
                    cited.update(site.evidence_ids)
            if cited - evidence_ids:
                raise ValueError(f"endpoint pair cites missing card evidence IDs: {sorted(cited - evidence_ids)}")
        for opportunity in self.model_opportunities:
            if opportunity.cwe != self.cwe:
                raise ValueError("model opportunity CWE does not match its case card")
            if set(opportunity.evidence_ids) - evidence_ids:
                raise ValueError("model opportunity cites evidence absent from its card")
        return self


class AgentActionArtifact(StrictModel):
    path: str
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    size_bytes: int | None = Field(default=None, ge=0)


class AgentActionLocation(StrictModel):
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    symbol: str | None = None

    @model_validator(mode="after")
    def check_lines(self) -> "AgentActionLocation":
        if self.end_line < self.start_line:
            raise ValueError("agent action end line precedes start line")
        return self


class AgentActionAlternative(StrictModel):
    hypothesis_id: str
    status: str
    reason: str
    evidence_ids: list[str] = Field(default_factory=list)


class AgentActionOutcome(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    OPERATIONAL_FAILURE = "operational_failure"
    DEFERRED = "deferred"
    UNKNOWN = "unknown"


class AgentAction(StrictModel):
    """Durable evidence of one agent inspection or implementation action."""

    action_id: str
    occurred_at: str
    agent_id: str
    action_type: str
    tool: str
    argv: list[str] = Field(default_factory=list)
    task_id: str | None = None
    snapshot_id: str | None = None
    case_id: str | None = None
    variant_id: str | None = None
    model_id: str | None = None
    candidate_id: str | None = None
    repository_root: str | None = None
    repository_tree_sha: str | None = None
    inspected_locations: list[AgentActionLocation] = Field(default_factory=list)
    input_artifacts: list[AgentActionArtifact] = Field(default_factory=list)
    output_artifacts: list[AgentActionArtifact] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    alternatives: list[AgentActionAlternative] = Field(default_factory=list)
    outcome: AgentActionOutcome
    summary: str
    next_state: str | None = None
    failure_code: str | None = None
    retry_of: str | None = None

    @model_validator(mode="after")
    def check_action(self) -> "AgentAction":
        if not any((self.task_id, self.case_id, self.model_id, self.candidate_id)):
            raise ValueError("agent action must identify a task, case, model, or candidate")
        if self.variant_id and not self.case_id:
            raise ValueError("variant_id requires case_id")
        if self.inspected_locations and not (self.repository_root and self.repository_tree_sha):
            raise ValueError("inspected code locations require repository root and tree SHA")
        for name in ("action_id", "agent_id", "action_type", "tool", "outcome", "summary"):
            if not getattr(self, name).strip():
                raise ValueError(f"agent action {name} must not be empty")
        return self


class ModelCandidate(StrictModel):
    """A general CodeQL data-extension tuple or QL library candidate."""

    model_id: str
    role: ModelRole
    cwe: int
    representation: ModelRepresentation = ModelRepresentation.DATA_EXTENSION
    codeql_type: str | None = None
    codeql_path: str | None = None
    codeql_kind: str
    codeql_tuple: list[str] = Field(default_factory=list)
    ql_source_path: str | None = None
    ql_source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    ql_symbol: str | None = None
    semantic_scope: str
    semantic_contract: str
    supporting_card_ids: list[str]
    evidence_ids: list[str]
    api_documentation_urls: list[str] = Field(default_factory=list)
    stock_model_status: str
    expected_nodes: list[str] = Field(default_factory=list)
    provenance_class: str = "agent_inspected"

    @model_validator(mode="after")
    def check_candidate(self) -> "ModelCandidate":
        if self.cwe not in SUPPORTED_CWES:
            raise ValueError(f"unsupported Plan 7 CWE: {self.cwe}")
        if not self.semantic_scope.strip() or not self.semantic_contract.strip():
            raise ValueError("model candidate needs general semantic scope and contract")
        if not self.supporting_card_ids or not self.evidence_ids:
            raise ValueError("model candidate needs source cards and evidence")
        if self.stock_model_status not in {"present", "absent"}:
            raise ValueError("model candidate must record stock model check")
        forbidden = re.compile(r"(?:CVE-\d{4}-\d+|GHSA-[0-9a-z-]+|/|\\|benchmarks?/|runs/)", re.I)
        if self.representation == ModelRepresentation.DATA_EXTENSION:
            if not all((self.codeql_type, self.codeql_path, self.codeql_tuple)):
                raise ValueError("data-extension candidate needs a CodeQL tuple")
            if any((self.ql_source_path, self.ql_source_sha256, self.ql_symbol)):
                raise ValueError("data-extension candidate cannot carry a QL library")
            if forbidden.search(self.codeql_type or "") or forbidden.search(self.codeql_path or ""):
                raise ValueError("CodeQL model type/path contains a case or repository-specific locator")
            expected_id = model_candidate_id(
                self.role, self.cwe, self.codeql_type or "", self.codeql_path or "",
                self.codeql_kind, self.codeql_tuple, self.semantic_scope,
            )
        else:
            if not all((self.ql_source_path, self.ql_source_sha256, self.ql_symbol)):
                raise ValueError("QL library candidate needs a hashed source file and symbol")
            if any((self.codeql_type, self.codeql_path, self.codeql_tuple)):
                raise ValueError("QL library candidate cannot carry a CodeQL tuple")
            expected_id = ql_model_candidate_id(
                self.role, self.cwe, self.ql_symbol or "",
                self.codeql_kind, self.ql_source_sha256 or "", self.semantic_scope,
            )
        if self.model_id != expected_id:
            raise ValueError("model_id does not match normalized general model semantics")
        return self


class ModelDecision(StrictModel):
    decision_id: str
    model_id: str
    state: ModelDecisionState
    actor: str
    decided_at: str
    reason: str
    prior_decision_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    validation_artifact: str | None = None
    validation_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def require_validation_for_acceptance(self) -> "ModelDecision":
        if self.state == ModelDecisionState.ACCEPTED and not (
            self.validation_artifact and self.validation_sha256
        ):
            raise ValueError("accepted models require a hashed cross-project validation artifact")
        return self


def model_candidate_id(
    role: ModelRole | str,
    cwe: int,
    codeql_type: str,
    codeql_path: str,
    codeql_kind: str,
    codeql_tuple: list[str],
    semantic_scope: str,
) -> str:
    from aisast.corpus.io import stable_id

    role_value = role.value if isinstance(role, ModelRole) else str(role)
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "role": role_value,
        "cwe": cwe,
        "type": " ".join(codeql_type.split()),
        "path": " ".join(codeql_path.split()),
        "kind": codeql_kind,
        "tuple": list(codeql_tuple),
        "semantic_scope": " ".join(semantic_scope.split()),
    }
    return stable_id("plan7-general-model-v1", normalized)


def ql_model_candidate_id(
    role: ModelRole | str, cwe: int, symbol: str,
    kind: str, source_sha256: str, semantic_scope: str,
) -> str:
    from aisast.corpus.io import stable_id

    return stable_id("plan7-general-ql-model-v1", {
        "schema_version": SCHEMA_VERSION,
        "role": role.value if isinstance(role, ModelRole) else str(role),
        "cwe": cwe,
        "symbol": symbol,
        "kind": kind,
        "source_sha256": source_sha256,
        "semantic_scope": " ".join(semantic_scope.split()),
    })


class ProposalState(StrEnum):
    PROPOSED = "proposed"
    UNKNOWN = "unknown"
    NO_SUPPORTED_PROPOSAL = "no_supported_proposal"
    OPERATIONAL_FAILURE = "operational_failure"


class ProposalCompletion(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    OPERATIONAL_FAILURE = "operational_failure"


class ProposalRecord(StrictModel):
    proposal_id: str
    case_id: str
    variant_id: str
    vulnerable_tree_sha: str
    cwe_claims: list[int] = Field(default_factory=list)
    state: ProposalState
    source_candidates: list[dict[str, Any]] = Field(default_factory=list)
    sink_candidates: list[dict[str, Any]] = Field(default_factory=list)
    pairs: list[dict[str, Any]] = Field(default_factory=list)
    evidence_map: list[dict[str, Any]] = Field(default_factory=list)
    repository_index_path: str | None = None
    repository_index_sha256: str | None = None
    omitted_work: list[dict[str, Any]] = Field(default_factory=list)
    codeql_hint_status: str = "not_run"
    llm_judgment_status: str = "not_run"
    llm_response_sha256: str | None = None
    searched_operations: list[str] = Field(default_factory=list)
    parse_failures: list[dict[str, Any]] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    execution_error: str | None = None
    created_at: str
    completion_status: ProposalCompletion = ProposalCompletion.INCOMPLETE
    candidate_pair_ledger_path: str | None = None
    candidate_pair_ledger_sha256: str | None = None
    candidate_pair_count: int = Field(default=0, ge=0)
    candidate_pair_status_counts: dict[str, int] = Field(default_factory=dict)
    source_inventory_path: str | None = None
    sink_inventory_path: str | None = None
    evidence_inventory_path: str | None = None
    evidence_inventory_sha256: str | None = None


class ReviewEligibility(StrEnum):
    ELIGIBLE = "eligible"
    EXCLUDED = "excluded"
    UNRESOLVED = "unresolved"
    UNKNOWN = "unknown"


class ReviewRecord(StrictModel):
    review_id: str
    case_id: str
    variant_id: str
    reviewer_id: str
    review_round: int = Field(ge=1)
    blind_to_proposals: bool = False
    blind_to_detector: bool = True
    reviewed_at: str
    input_artifact_sha256: str
    eligibility: str
    reviewed_cwes: list[int] = Field(default_factory=list)
    attacker_capability: str | None = None
    preconditions: list[str] = Field(default_factory=list)
    endpoint_pair_ids: list[str] = Field(default_factory=list)
    unresolved_fields: list[str] = Field(default_factory=list)
    inspected_absent_fields: list[str] = Field(default_factory=list)
    rationale: str
    adjudicates_review_ids: list[str] = Field(default_factory=list)


class ReviewSubmission(StrictModel):
    """One person's independent annotation; one submission per variant."""

    review_id: str
    case_id: str
    variant_id: str
    reviewer_id: str
    review_round: int = Field(default=1, ge=1)
    blind_to_proposals: bool
    blind_to_detector: bool = True
    reviewed_at: str
    input_artifact_sha256: str
    eligibility: ReviewEligibility
    reviewed_cwes: list[int] = Field(default_factory=list)
    attacker_capability: str | None = None
    preconditions: list[str] = Field(default_factory=list)
    vulnerable_behavior: str | None = None
    fixed_behavior: str | None = None
    pairs: list[EndpointPair] = Field(default_factory=list)
    evidence_records: list[ReviewEvidence] = Field(default_factory=list)
    unresolved_fields: list[str] = Field(default_factory=list)
    inspected_absent_fields: list[str] = Field(default_factory=list)
    rationale: str
    adjudicates_review_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_submission_metadata(self) -> "ReviewSubmission":
        if not self.review_id.strip() or not self.reviewer_id.strip():
            raise ValueError("review_id and reviewer_id must be non-empty")
        if self.review_id != self.review_id.strip() or self.reviewer_id != self.reviewer_id.strip():
            raise ValueError("review_id and reviewer_id must not have surrounding whitespace")
        if not self.rationale.strip():
            raise ValueError("review rationale must be non-empty")
        if self.adjudicates_review_ids and self.review_round < 2:
            raise ValueError("an adjudication must use review_round >= 2")
        if len(self.adjudicates_review_ids) != len(set(self.adjudicates_review_ids)):
            raise ValueError("adjudicates_review_ids must be unique")
        return self
