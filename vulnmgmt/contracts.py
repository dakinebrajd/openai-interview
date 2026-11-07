"""Strict versioned boundaries; structural validity never proves evidence truth."""

from datetime import datetime, timezone
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import (AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field,
                      HttpUrl, JsonValue, StringConstraints, model_validator)

Nonempty = Annotated[str, StringConstraints(min_length=1, max_length=10000)]
CVE = Annotated[str, StringConstraints(pattern=r'^CVE-[0-9]{4}-[0-9]{4,}$')]
Digest = Annotated[str, StringConstraints(pattern=r'^[a-f0-9]{64}$')]
Rank = Annotated[int, Field(ge=0, le=4)]
Revision = Annotated[int, Field(ge=0)]
UtcTime = Annotated[AwareDatetime, AfterValidator(lambda v: v.astimezone(timezone.utc))]
FindingStatus = Literal['Open', 'In Remediation', 'Pending Verification', 'Verified Remediated']
Scanner = Literal['Tenable', 'Defender']


class Contract(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid', frozen=True, allow_inf_nan=False)
    schema_version: Literal['1'] = '1'
    workspace_id: UUID
    scenario_version_id: UUID
    correlation_id: UUID
    mode: Literal['live', 'replay']


class ScannerFinding(Contract):
    scanner: Scanner
    scanner_tenant: Nonempty
    native_scan_id: Nonempty
    native_asset_id: Nonempty
    native_finding_id: Nonempty
    asset_id: UUID
    component_id: UUID
    observed_at: UtcTime
    raw_severity: Nonempty
    mapped_severity_rank: Rank | None
    mapping_version: Nonempty
    cve_ids: Annotated[list[CVE], Field(min_length=1)]
    payload: dict[str, JsonValue]

    @model_validator(mode='after')
    def unique_cves(self) -> Self:
        if len(set(self.cve_ids)) != len(self.cve_ids):
            raise ValueError('Duplicate CVEs in one observation')
        return self


class NormalizedVulnerability(Contract):
    id: UUID
    asset_id: UUID
    component_id: UUID
    cve_id: CVE
    source_raw_ids: Annotated[list[UUID], Field(min_length=1)]
    max_severity_rank: Rank | None
    has_unknown_severity: bool
    first_seen: UtcTime
    last_seen: UtcTime
    status: FindingStatus
    revision: Revision

    @model_validator(mode='after')
    def ordered(self) -> Self:
        if self.first_seen > self.last_seen:
            raise ValueError('first_seen must precede last_seen')
        if self.max_severity_rank is None and not self.has_unknown_severity:
            raise ValueError('Missing severity must be explicitly unknown')
        return self


class RemediationEvidence(Contract):
    source_id: UUID
    url: HttpUrl
    publisher: Nonempty
    retrieved_at: UtcTime
    published_at: UtcTime | None = None
    fetch_status: Literal['Success', 'Failed']
    content_hash: Digest | None = None
    snapshot: dict[str, JsonValue] | None = None
    error: Nonempty | None = None
    cve_id: CVE | None = None
    statement: Nonempty
    supporting_excerpt: Nonempty | None = None
    validation_status: Literal['Proposed', 'Confirmed', 'Rejected']
    validator: Nonempty | None = None
    validated_at: UtcTime | None = None

    @model_validator(mode='after')
    def grounded(self) -> Self:
        if self.fetch_status == 'Success' and (self.content_hash is None or self.snapshot is None or self.error):
            raise ValueError('Successful retrieval requires hash/snapshot and no error')
        if self.fetch_status == 'Failed' and (not self.error or self.validation_status == 'Confirmed'):
            raise ValueError('Failed retrieval cannot confirm a claim')
        if self.validation_status == 'Confirmed' and not (
                self.validator and self.validated_at and self.supporting_excerpt):
            raise ValueError('Confirmation requires supporting extract and validator')
        return self


class RemediationBatch(Contract):
    id: UUID
    asset_id: UUID
    action_id: UUID
    action_revision: Revision
    cycle: Annotated[int, Field(ge=1)]
    member_ids: Annotated[list[UUID], Field(min_length=1)]
    applicability_claim_ids: Annotated[list[UUID], Field(min_length=1)]
    status: Literal['Proposed', 'Confirmed', 'Active', 'Pending Verification', 'Verified Remediated', 'Cancelled']
    revision: Revision

    @model_validator(mode='after')
    def members_unique(self) -> Self:
        if len(set(self.member_ids)) != len(self.member_ids):
            raise ValueError('Members must be unique')
        return self


class Ticket(Contract):
    id: UUID
    batch_id: UUID
    action_key: Digest
    origin: Literal['seeded', 'generated']
    proposal_id: UUID | None
    status: Literal['Open', 'Simulated Open', 'In Progress', 'Pending Verification', 'Closed']
    created_at: UtcTime
    revision: Revision

    @model_validator(mode='after')
    def proposal_required(self) -> Self:
        if (self.origin == 'generated') != (self.proposal_id is not None):
            raise ValueError('Only generated tickets require proposal IDs')
        return self


class StatusTransition(Contract):
    asset_cve_id: UUID
    expected_revision: Revision
    from_status: FindingStatus
    to_status: FindingStatus
    actor_id: Nonempty
    reason: Nonempty
    occurred_at: UtcTime
    verification_event_id: UUID | None = None
    reply_claim_id: UUID | None = None

    @model_validator(mode='after')
    def allowed(self) -> Self:
        allowed = {
            'Open': {'In Remediation', 'Pending Verification'},
            'In Remediation': {'Pending Verification'},
            'Pending Verification': {'Open', 'Verified Remediated'},
            'Verified Remediated': {'Open'},
        }
        if self.to_status not in allowed[self.from_status]:
            raise ValueError('Invalid status transition')
        if self.to_status in ('Verified Remediated', 'Open') and self.verification_event_id is None:
            raise ValueError('Scanner verification event is required')
        return self
