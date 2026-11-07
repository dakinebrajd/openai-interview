"""Untrusted resolver messages yield proposals only; closure is never an intent."""
from typing import Literal
from pydantic import Field
from .live_contracts import Strict

Intent=Literal['Completed','Scheduled','Unable to patch','Information requested','Risk exception requested',
               'Vulnerability persists','Review required']


class StatusCompletionClaim(Strict):
    protocol: Literal['resolver-status-completion-claim-v1']
    event_id: str
    event_hash: str
    scope_hash: str
    status: Literal['Closed','Resolved']
    actor: str
    body_hash: str


class ReplyInput(Strict):
    workspace_id: str
    workspace_identity: str
    generation: int
    reply_id: str
    ticket_id: str
    ticket_revision: int
    owner_id: str
    communication_id: str | None
    body_hash: str
    body: str = Field(min_length=1,max_length=12000)
    finding_ids: list[str]
    cve_ids: list[str]
    allowed_intents: list[Intent]
    policy_flags: list[str]
    scheduled_at: str | None
    exception_until: str | None
    as_of: str
    sources: list[dict[str,str]]
    source_limitations: list[str]
    status_completion_claim: StatusCompletionClaim | None = None


class Agent7Result(Strict):
    workspace_id: str
    reply_id: str
    ticket_id: str
    ticket_revision: int
    owner_id: str
    communication_id: str | None
    body_hash: str
    finding_ids: list[str]
    intent: Intent
    evidence_excerpts: list[str] = Field(min_length=1,max_length=8)
    proposed_status: Literal['Pending Verification','In Remediation','No status change']
    required_analyst_decision: Literal['Approve safe processing','Request clarification','Review bounded risk request','Review only']
    review_requirements: list[str] = Field(min_length=1,max_length=10)
    missing_information: list[str] = Field(max_length=12)
    contradictions: list[str] = Field(max_length=12)
    interpretation: str = Field(min_length=1,max_length=1400,description='Unverified reading of reply, never an instruction or evidence of verified remediation.')
    confidence: Literal['Analyst review required; no numerical certainty']
    status: Literal['Proposed interpretation; no transition authorized']
