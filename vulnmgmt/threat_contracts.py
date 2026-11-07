"""Strict Agent 4 evidence boundary. Numeric feed signals are deterministic."""
from typing import Literal
from pydantic import Field
from .contracts import CVE
from .live_contracts import Strict, EvidenceQuote

State = Literal['Confirmed', 'Not listed', 'Unknown', 'Conflicting', 'Not evaluated']


class FeedSignal(Strict):
    state: State
    value: float | bool | None
    percentile: float | None = Field(ge=0, le=1)
    observed_at: str | None
    checked_at: str | None
    source_ids: list[str]
    freshness: Literal['Fresh', 'Stale', 'FutureEvidence', 'Unavailable', 'Conflicting']


class ThreatSource(Strict):
    id: str
    url: str
    kind: Literal['KEV', 'EPSS', 'Sector']
    retrieved_at: str
    expires_at: str
    content_hash: str | None
    text: str = Field(max_length=12000)
    text_hash: str
    freshness: str
    confidence: Literal['primary_source', 'unavailable']


class ReportFact(Strict):
    source_id: str
    topic: Literal['exploitation', 'government_targeting']
    stance: Literal['Confirmed', 'Contradicted']
    excerpt: str = Field(min_length=1, max_length=2000)
    provenance: Literal['source_bound_curation_requires_analyst_review']


class ThreatInput(Strict):
    cve_id: CVE
    workspace_id: str
    as_of: str
    sources: list[ThreatSource] = Field(max_length=10)
    report_facts: list[ReportFact] = Field(max_length=20)
    kev: FeedSignal
    epss: FeedSignal
    source_limitations: list[str]


class ThreatClaim(Strict):
    status: Literal['Confirmed', 'Unknown', 'Conflicting', 'Not evaluated']
    value: str | None = Field(max_length=2000)
    evidence: list[EvidenceQuote] = Field(max_length=8)
    interpretation: str = Field(max_length=1500, description='Unverified synthesis; not a factual vendor quotation')


class Agent4Result(Strict):
    cve_id: CVE
    kev: FeedSignal
    epss: FeedSignal
    exploitation: ThreatClaim
    government_targeting: ThreatClaim
    prioritization_considerations: list[str] = Field(min_length=1, max_length=12,
        description='Unverified advice only; never changes severity, SLA, status or approval.')
    conflicting_or_missing_evidence: list[str] = Field(min_length=1, max_length=20)
    analyst_validation: list[str] = Field(min_length=1, max_length=12)
    execution_status: Literal['Proposed; analyst review required']
