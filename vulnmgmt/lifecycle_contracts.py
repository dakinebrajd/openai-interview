"""Deterministic local lifecycle inputs; no model execution or sending interfaces."""
from typing import Literal
from uuid import UUID
from pydantic import Field, model_validator
from .contracts import Contract, Nonempty, Revision, UtcTime
from .research_contracts import ResearchModel


class RenderedDraft(ResearchModel):
    subject: Nonempty
    ticket_description: Nonempty
    email_body: Nonempty
    to: Nonempty


class AnalystDecision(Contract):
    operation_key: Nonempty
    target_id: UUID
    payload_hash: Nonempty
    analyst_id: Nonempty
    reason: Nonempty
    decision: Literal['Approved', 'Rejected']
    decided_at: UtcTime


class ResolverReply(Contract):
    operation_key: Nonempty
    ticket_id: UUID
    owner_id: UUID
    body: Nonempty
    received_at: UtcTime
    scheduled_at: UtcTime | None = None
    exception_until: UtcTime | None = None
    communication_id: UUID | None = None


class ScannerResult(Contract):
    operation_key: Nonempty
    ticket_id: UUID
    assessed_at: UtcTime
    recorded_at: UtcTime
    scan_status: Literal['Success', 'Partial', 'Failed']
    outcomes: dict[str, Literal['Pass', 'Fail', 'Inconclusive']]

    @model_validator(mode='after')
    def ordered(self):
        if self.assessed_at > self.recorded_at or not self.outcomes:
            raise ValueError('Scanner assessment must be nonempty and precede recording')
        return self
