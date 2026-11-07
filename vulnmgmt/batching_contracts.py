"""Agent 3 research contracts; proposals confer no operational authority."""
from typing import Literal
from pydantic import Field,model_validator
import json
from .services import digest
from .contracts import CVE
from .live_contracts import Strict, EvidenceQuote
from .research_contracts import RemediationRule


class BatchSource(Strict):
    id: str
    url: str
    kind: str
    retrieved_at: str
    content_hash: str
    text: str = Field(max_length=16000)
    text_hash: str
    provenance: str


class ResearchReference(Strict):
    step_id: str
    run_id: str
    role: Literal[2, 4]
    cve_id: CVE
    origin: str
    proposal_hash: str | None
    review_status: str
    content_json: str = Field(max_length=16000)
    source_provenance_json: str = Field(max_length=16000)


class BatchFinding(Strict):
    finding_id: str
    cve_id: CVE
    asset_id: str
    component_id: str
    product: str
    published_products: list[str]
    installed_version: str | None
    status: str
    severity: str
    applicability: Literal['Synthetic assumption', 'Unknown', 'Conflicting Evidence']
    assumption: str | None
    remediation_evidence: list[EvidenceQuote]
    historical_instruction: str | None
    exclusion: Literal['Cross-asset', 'Different component', 'Not unresolved', 'Conflicting vendor guidance'] | None


class BatchOption(Strict):
    action_id: str
    rule: RemediationRule
    source_id: str
    evidence: list[EvidenceQuote]
    finding_ids: list[str]
    existing_proposal_ids: list[str]


class SharedResearchText(Strict):
    sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    json_text: str = Field(max_length=16000)


class BatchInput(Strict):
    workspace_id: str
    asset_id: str
    asset_key: str
    component_id: str
    component_key: str
    as_of: str
    findings: list[BatchFinding] = Field(min_length=1, max_length=20)
    options: list[BatchOption] = Field(max_length=10)
    research: list[ResearchReference] = Field(max_length=40)
    shared_research_text: list[SharedResearchText] = Field(default_factory=list,max_length=80)
    sources: list[BatchSource] = Field(max_length=30)
    source_limitations: list[str]

    @model_validator(mode='after')
    def complete_shared_text_integrity(self):
        catalogue={}
        for item in self.shared_research_text:
            if item.sha256 in catalogue or digest(item.json_text)!=item.sha256:
                raise ValueError('Duplicate or altered shared research text')
            json.loads(item.json_text)
            catalogue[item.sha256]=item.json_text
        used=set()
        for ref in self.research:
            for value in (ref.content_json,ref.source_provenance_json):
                parsed=json.loads(value)
                if isinstance(parsed,dict) and 'shared_research_text_sha256' in parsed:
                    if set(parsed)!={'shared_research_text_sha256'} or parsed['shared_research_text_sha256'] not in catalogue:
                        raise ValueError('Missing or malformed shared research reference')
                    used.add(parsed['shared_research_text_sha256'])
        if used!=set(catalogue):raise ValueError('Unreferenced shared research text')
        return self


class ProposedGroup(Strict):
    action_id: str
    finding_ids: list[str] = Field(min_length=2, max_length=20)
    cve_ids: list[CVE] = Field(min_length=2, max_length=20)
    product: str
    affected_versions: str = Field(description='Prefer exact rule.affected_min + " to " + rule.affected_max_inclusive. Only its exact cited vendor range sentence may be deterministically normalized; no new boundaries.')
    historical_target_version: str
    historical_instruction: str
    vendor_evidence: list[EvidenceQuote] = Field(min_length=1, max_length=10,
        description='Copy exactly the option evidence identities and verbatim text. List permutation is canonicalized; missing/duplicate/altered or differently associated citations are rejected.')
    applicability: Literal['Synthetic assumption', 'Unknown']
    decision: Literal['Shared action proposed', 'Needs applicability review']
    interpretation: str = Field(min_length=1, max_length=1800,
        description='Unverified reasoning; explain equivalence and historical/applicability limits. No new patch facts.')


class ExcludedFinding(Strict):
    finding_id: str
    reason: Literal['Cross-asset', 'Different component', 'Not unresolved', 'Conflicting vendor guidance',
                    'No verified shared action', 'Separate remediation', 'Analyst review required']
    interpretation: str = Field(min_length=1, max_length=1200, description='Unverified explanation only')


class Agent3Result(Strict):
    workspace_id: str
    asset_id: str
    component_id: str
    batches: list[ProposedGroup] = Field(max_length=10)
    excluded: list[ExcludedFinding] = Field(max_length=20)
    research_step_ids: list[str] = Field(max_length=40)
    conflicting_or_missing_evidence: list[str] = Field(min_length=1, max_length=20)
    threat_considerations: list[str] = Field(min_length=1, max_length=12,
        description='Unverified prioritization only; cannot establish action equivalence or change SLA/severity.')
    analyst_validation: list[str] = Field(min_length=1, max_length=12)
    status: Literal['Proposed; analyst review required']
