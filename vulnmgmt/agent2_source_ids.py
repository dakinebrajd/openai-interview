"""Per-request Agent 2 citation constraints; no transport, remapping or global mutation."""
from copy import deepcopy
from typing import Literal
from uuid import UUID
from pydantic import create_model
from .live_contracts import Agent2Result,EvidenceQuote,ResearchClaim,LiveResearchError


def bound_agent2_output(supplied):
    """Preserve the full strict contract, narrowing only citation IDs for this input."""
    sources=supplied.get('sources') if isinstance(supplied,dict) else None
    if not isinstance(sources,list) or not sources or len(sources)>1000:
        raise LiveResearchError('Agent 2 requires a bounded nonempty citation source list.')
    ids=[]
    for source in sources:
        value=source.get('id') if isinstance(source,dict) else None
        try:valid=isinstance(value,str) and str(UUID(value))==value
        except (ValueError,TypeError,AttributeError):valid=False
        if not valid:
            raise LiveResearchError('Agent 2 citation inputs require canonical source UUIDs.')
        ids.append(value)
    if len(set(ids))!=len(ids):
        raise LiveResearchError('Agent 2 citation input UUIDs must be unique.')
    ids=tuple(sorted(ids))
    # Public Pydantic/SDK output types enforce membership both in the provider's
    # strict JSON Schema and in the SDK's local TypeAdapter response validation.
    field=deepcopy(EvidenceQuote.model_fields['source_id'])
    field.description='Copy the exact supplied sources[].id UUID. Hashes are integrity metadata, never citation identifiers.'
    quote=create_model('RunEvidenceQuote',__base__=EvidenceQuote,source_id=(Literal[ids],field))
    claim=create_model('RunResearchClaim',__base__=ResearchClaim,
                       evidence=(list[quote],deepcopy(ResearchClaim.model_fields['evidence'])))
    fields=('description','affected_product','affected_versions','vendor_remediation','advisory_identifiers')
    output=create_model('RunAgent2Result',__base__=Agent2Result,
                        **{name:(claim,deepcopy(Agent2Result.model_fields[name])) for name in fields})
    # Stay inside the documented Structured Outputs enum limits. No unrestricted
    # fallback is permitted when a caller supplies an invalid/oversized ID set.
    enums=[]
    def collect(value):
        if isinstance(value,dict):
            if 'enum' in value:enums.append(value['enum'])
            for child in value.values():collect(child)
        elif isinstance(value,list):
            for child in value:collect(child)
    collect(output.model_json_schema())
    if sum(len(values) for values in enums)>1000 or any(
            len(values)>250 and sum(len(value) for value in values if isinstance(value,str))>15000 for values in enums):
        raise LiveResearchError('Agent 2 citation source IDs exceed strict schema limits.')
    return output
