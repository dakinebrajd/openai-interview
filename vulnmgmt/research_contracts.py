"""Typed M3 reasoning boundaries, with explicit evidence and replay origins."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from .contracts import CVE, UtcTime


class ResearchModel(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid', allow_inf_nan=False)


class Citation(ResearchModel):
    source_id: str
    excerpt: str = Field(min_length=1, max_length=2000)


class Guidance(ResearchModel):
    cve_id: CVE
    affected_source_id: str
    affected_json: str
    vendor_source_id: str | None
    instructions: str | None
    fixed_version: str | None
    status: Literal['Supported', 'Missing', 'Conflicting']
    citations: list[Citation]
    gaps: list[str]
    confidence: Literal['primary_source', 'review_required']


class ThreatAssessment(ResearchModel):
    cve_id: CVE
    kev_member: bool | None
    kev_source_id: str | None
    kev_added_date: str | None
    kev_action: str | None
    epss_score: float | None = Field(ge=0, le=1)
    epss_percentile: float | None = Field(ge=0, le=1)
    epss_date: str | None
    epss_source_id: str | None
    exploitation: Literal['Confirmed in KEV', 'Documented in advisory', 'Unknown']
    exploitation_citations: list[Citation]
    sector_targeting: Literal['Supported', 'Unknown', 'Conflicting']
    sector_citations: list[Citation]
    gaps: list[str]


class ApplicabilityAssumption(ResearchModel):
    asset_key: str
    component_key: str
    product: str
    installed_version: str
    expected_component_revision: int = Field(ge=0)
    label: Literal['SYNTHETIC ASSUMPTION - NOT SCANNER EVIDENCE']


class RemediationRule(ResearchModel):
    action_key: str
    product: str
    affected_min: str
    affected_max_inclusive: str
    target_version: str
    cve_ids: list[CVE]
    source_id: str
    instruction: str
    affected_excerpt: str
    warning: str


class BatchCandidate(ResearchModel):
    asset_id: str
    action_key: str
    member_ids: list[str]
    source_ids: list[str]
    assumption_label: str
    status: Literal['Proposed']
    requires_analyst_review: Literal[True]


class ResearchInput(ResearchModel):
    cve_ids: list[CVE]
    source_ids: list[str]
    mode: Literal['replay', 'live']
    effective_at: UtcTime


class RemediationOutput(ResearchModel):
    origin: Literal['human_curated_source_backed_replay', 'live_model']
    guidance: list[Guidance]


class ThreatOutput(ResearchModel):
    assessments: list[ThreatAssessment]


class BatchingOutput(ResearchModel):
    candidates: list[BatchCandidate]
    review_reasons: list[str]
