"""Agent 6 composes drafts from source/policy facts; no operational authority."""
from typing import Literal
from pydantic import Field
from .live_contracts import Strict
from .batching_contracts import BatchSource


class DraftCitation(Strict):
    fact_id: str
    source_id: str
    excerpt: str = Field(min_length=1,max_length=2000)


class DraftFact(Strict):
    id: str
    category: Literal['Verified source fact','Deterministic policy fact','Synthetic assumption','Unknown','Warning']
    text: str = Field(min_length=1,max_length=16000)


class DraftInput(Strict):
    workspace_id: str
    workspace_identity: str
    generation: int
    scope_id: str
    snapshot_binding_hash: str
    snapshot_material_hash: str
    as_of: str
    asset_id: str
    resolver_group_id: str
    recipient: str
    finding_ids: list[str]
    cve_ids: list[str]
    hypothetical_deadline: str | None
    facts: list[DraftFact] = Field(min_length=1,max_length=64)
    citations: list[DraftCitation] = Field(max_length=30)
    sources: list[BatchSource] = Field(max_length=30)
    source_limitations: list[str]


class ConditionalInterpretation(Strict):
    basis_fact_ids: list[str] = Field(min_length=1,max_length=12)
    reasoning: str = Field(min_length=1,max_length=1200,
        description='Unverified conditional reasoning only. No new numbers, CVEs, versions, patches, URLs, recipients, compromise or remediation assertions. Facts are rendered separately.')


class Composition(Strict):
    fact_order: list[str] = Field(min_length=1,max_length=64,
        description='Every supplied fact ID exactly once, starting with synthetic-label. The application renders their unchanged source/policy text.')
    interpretation_indices: list[int] = Field(max_length=8)


class Agent6Result(Strict):
    workspace_id: str
    scope_id: str
    snapshot_binding_hash: str
    asset_id: str
    resolver_group_id: str
    recipient: str
    finding_ids: list[str]
    cve_ids: list[str]
    hypothetical_deadline: str | None
    citations: list[DraftCitation] = Field(max_length=30)
    subject_style: Literal['Remediation review','Remediation plan requested']
    consolidated_report: Composition
    ticket_description: Composition
    synthetic_email: Composition
    interpretations: list[ConditionalInterpretation] = Field(min_length=1,max_length=8)
    owner_action: Literal['Validate applicability and current vendor guidance; propose a schedule and provide subsequent scanner evidence.']
    analyst_validation: list[str] = Field(min_length=1,max_length=10,
        description='Unverified review requests only; no new patch, version, CVE, URL or factual assertion.')
    status: Literal['Draft; analyst review required']
