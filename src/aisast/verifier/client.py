from __future__ import annotations

import json
import hashlib
import time
from copy import deepcopy
from typing import Any, Callable

import httpx

from aisast.models import EvidencePacket, VerificationResult, Verdict
from aisast.verifier.prompts import render_prompt
from aisast.verifier.schemas import VerificationError


OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "candidate_id": {"type": "string"},
        "cwe": {"type": "integer"},
        "verdict": {"type": "string", "enum": ["VULNERABLE", "NOT_VULNERABLE", "NEEDS_MORE_CONTEXT", "UNRESOLVED"]},
        "source_evidence": {"type": "array", "maxItems": 3, "items": {"type": "string"}},
        "sink_evidence": {"type": "array", "maxItems": 3, "items": {"type": "string"}},
        "sanitizer_evidence": {"type": "array", "maxItems": 3, "items": {"type": "string"}},
        "explanation": {"type": "string", "maxLength": 384},
        "missing_symbols": {"type": "array", "maxItems": 3, "items": {"type": "string", "maxLength": 96}},
    },
    "required": ["candidate_id", "cwe", "verdict", "source_evidence", "sink_evidence", "sanitizer_evidence", "explanation", "missing_symbols"],
    "additionalProperties": False,
}


class VerifierClient:
    def __init__(self, endpoint: str, model: str, temperature: float = 0.0, top_p: float = 1.0, max_tokens: int = 700, timeout: float = 120, max_retries: int = 1, transport: httpx.BaseTransport | None = None, attempt_sink: Callable[[dict[str, Any]], None] | None = None, context_window: int | None = None, citation_contract: bool = False, decision_contract: bool = False) -> None:
        self.endpoint = endpoint.rstrip("/") + "/chat/completions"
        self.model, self.temperature, self.top_p, self.max_tokens, self.timeout, self.max_retries = model, temperature, top_p, max_tokens, timeout, min(max_retries, 1)
        self.transport = transport
        self.attempt_sink = attempt_sink
        self.context_window = context_window
        self.citation_contract = citation_contract
        self.decision_contract = decision_contract

    def prepare_packet(self, packet: EvidencePacket, guided: bool = True) -> EvidencePacket:
        if self.context_window is None:
            return packet
        from aisast.verifier.budget import fit_packet
        base = self.endpoint.removesuffix('/chat/completions').removesuffix('/v1')
        def count(prompt: str) -> int:
            if self.decision_contract:
                from aisast.verifier.contracts import add_decision_contract
                prompt = add_decision_contract(prompt)
            try:
                with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                    wrapped = client.post(base + '/apply-template', json={
                        'messages': [{'role': 'system', 'content': 'Return only valid JSON.'},
                                     {'role': 'user', 'content': prompt}], 'add_generation_prompt': True})
                    wrapped.raise_for_status()
                    tokenized = client.post(base + '/tokenize', json={
                        'content': wrapped.json()['prompt'], 'add_special': True})
                    tokenized.raise_for_status()
                    return len(tokenized.json()['tokens'])
            except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
                raise VerificationError('Prompt token measurement failed: ' + str(exc),
                                        prompt=prompt, model=self.model) from exc
        return fit_packet(packet, count, self.context_window - self.max_tokens - 64, guided)

    def verify(self, packet: EvidencePacket, guided: bool = True) -> tuple[VerificationResult, dict[str, Any]]:
        packet = self.prepare_packet(packet, guided)
        from aisast.verifier.contracts import bound_schema, decision_prompt
        prompt = decision_prompt(packet, guided) if self.decision_contract else render_prompt(packet, guided)
        schema = bound_schema(packet, self.citation_contract)
        # The pinned llama.cpp server applies its grammar only with this
        # json_object/schema form; json_schema/schema was accepted but ignored.
        payload = {"model": self.model, "temperature": self.temperature, "top_p": self.top_p, "max_tokens": self.max_tokens, "messages": [{"role": "system", "content": "Return only valid JSON."}, {"role": "user", "content": prompt}], "response_format": {"type": "json_object", "schema": schema}}
        started = time.perf_counter()
        last_error: Exception | None = None
        attempt_log: list[dict[str, Any]] = []
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
        for attempt in range(self.max_retries + 1):
            attempt_started = time.perf_counter()
            requested_max_tokens = payload["max_tokens"]
            body: Any = None
            raw_response: str | None = None
            if self.attempt_sink:
                self.attempt_sink({
                    "candidate_id": packet.candidate.candidate_id,
                    "phase": "request_started", "attempt": attempt + 1,
                    "prompt": prompt, "prompt_hash": prompt_hash, "model": self.model,
                    "requested_max_tokens": requested_max_tokens,
                    "output_schema": schema,
                })
            try:
                with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                    response = client.post(self.endpoint, json=payload)
                    raw_response = response.text
                    if self.attempt_sink:
                        self.attempt_sink({
                            "candidate_id": packet.candidate.candidate_id,
                            "phase": "response_received", "attempt": attempt + 1,
                            "prompt_hash": prompt_hash, "model": self.model,
                            "http_status": response.status_code,
                            "latency_seconds": time.perf_counter() - attempt_started,
                            "raw_response_base64": __import__("base64").b64encode(
                                response.content
                            ).decode("ascii"),
                            "raw_response_sha256": hashlib.sha256(response.content).hexdigest(),
                        })
                    response.raise_for_status()
                    body = response.json()
                    raw_response = json.dumps(body, sort_keys=True, ensure_ascii=False)
                    if body["choices"][0].get("finish_reason") == "length":
                        raise ValueError("Model output stopped at the completion-token limit")
                    message = body["choices"][0]["message"]
                    content = message.get("content") or message.get("reasoning_content", "")
                    if isinstance(content, list): content = "".join(p.get("text", "") for p in content)
                    data = self._parse_json(content)
                    if "verdict" not in data or "candidate_id" not in data:
                        raise ValueError("model output omits candidate_id or verdict")
                    parsed = VerificationResult.model_validate(data)
                    usage = body.get("usage", {}) or {}
                attempt_log.append({"attempt": attempt + 1, "status": "success",
                                    "latency_seconds": time.perf_counter() - attempt_started,
                                    "requested_max_tokens": requested_max_tokens,
                                    "finish_reason": body["choices"][0].get("finish_reason"),
                                    "usage": usage})
                if self.attempt_sink:
                    self.attempt_sink({
                        "candidate_id": packet.candidate.candidate_id,
                        "phase": "response_validated", "attempt": attempt + 1,
                        "prompt_hash": prompt_hash, "model": self.model,
                        "usage": usage,
                        "latency_seconds": time.perf_counter() - attempt_started,
                    })
                return parsed, {"prompt": prompt, "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest(), "model": self.model, "raw": body, "input_tokens": usage.get("prompt_tokens"), "output_tokens": usage.get("completion_tokens"), "attempt": attempt + 1, "attempt_log": attempt_log, "latency_seconds": time.perf_counter() - started, "prompt_budget": [row for row in packet.context_resolution if row.get("kind") == "prompt_token_budget"]}
            except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
                last_error = exc
                attempt_row = {"attempt": attempt + 1, "status": "error",
                               "latency_seconds": time.perf_counter() - attempt_started,
                               "error_type": type(exc).__name__,
                               "timeout": isinstance(exc, httpx.TimeoutException),
                               "error": str(exc)}
                attempt_row["requested_max_tokens"] = requested_max_tokens
                if isinstance(body, dict) and body.get("choices"):
                    attempt_row["finish_reason"] = body["choices"][0].get("finish_reason")
                    attempt_row["usage"] = body.get("usage", {})
                    # A bounded schema reduces output volume but cannot promise
                    # an exact tokenizer length. Preserve the same evidence and
                    # retry once with more output space, only when measured usage
                    # proves it fits. Never split the packet or accept partial JSON.
                    prompt_tokens = (body.get("usage") or {}).get("prompt_tokens")
                    if (attempt_row["finish_reason"] == "length" and self.context_window
                            and isinstance(prompt_tokens, int) and prompt_tokens >= 0):
                        available = self.context_window - prompt_tokens - 64
                        retry_tokens = min(self.max_tokens * 2, available)
                        if retry_tokens > requested_max_tokens:
                            payload["max_tokens"] = retry_tokens
                            attempt_row["retry_max_tokens"] = retry_tokens
                if raw_response is not None:
                    attempt_row["raw_response"] = raw_response
                    attempt_row["raw_response_sha256"] = hashlib.sha256(
                        raw_response.encode("utf-8")
                    ).hexdigest()
                attempt_log.append(attempt_row)
                if self.attempt_sink:
                    self.attempt_sink({
                        "candidate_id": packet.candidate.candidate_id,
                        "phase": "attempt_failed", "prompt_hash": prompt_hash,
                        "model": self.model, **attempt_row,
                    })
        raise VerificationError(
            f"verification failed after retry: {last_error}", attempt_log=attempt_log,
            prompt=prompt, prompt_hash=prompt_hash, model=self.model,
        )

    @staticmethod
    def _parse_json(content: str) -> dict[str, Any]:
        """Parse strict JSON while removing common local-server channel wrappers."""
        text = content.strip()
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            start, end = text.find("{"), text.rfind("}")
            if start < 0 or end <= start:
                raise
            value = json.loads(text[start:end + 1])
        if not isinstance(value, dict):
            raise ValueError("model output must be a JSON object")
        return value

    @staticmethod
    def system_error(candidate_id: str, explanation: str) -> VerificationResult:
        return VerificationResult(candidate_id=candidate_id, verdict=Verdict.SYSTEM_ERROR, explanation=explanation)
