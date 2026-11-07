"""Request-local complete research inventory for Agent 3 generation; no repair."""
from typing import Literal
from uuid import UUID
from pydantic import Field,create_model,model_validator
from .batching_contracts import BatchInput,Agent3Result
from .live_contracts import LiveResearchError


def bound_agent3_output(supplied):
    s=BatchInput.model_validate(supplied)
    ids=tuple(reference.step_id for reference in s.research)
    if len(ids)!=len(set(ids)):
        raise LiveResearchError('Agent 3 supplied research step identities must be unique.')
    for value in ids:
        try:valid=str(UUID(value))==value
        except (ValueError,TypeError,AttributeError):valid=False
        if not valid:
            raise LiveResearchError('Agent 3 requires canonical supplied research-step UUIDs.')
    expected=frozenset(ids)
    item=Literal[ids] if ids else str
    field=Field(min_length=len(ids),max_length=len(ids),
        description='Complete supplied research[].step_id audit inventory, each exactly once. Include every supplied Agent2/4 step, including captured replay and dated/stale observations. Order is irrelevant. Inventory completeness grants no freshness endorsement, analyst approval or batch authority. Empty input research requires [].')

    @model_validator(mode='after')
    def complete_research_inventory(self):
        actual=self.research_step_ids
        if len(actual)!=len(set(actual)) or set(actual)!=expected:
            raise ValueError('Agent 3 must reference the complete supplied research-step set exactly once.')
        return self  # Validate only; do not append, sort, filter or remap output.

    return create_model('RequestBoundAgent3Result',__base__=Agent3Result,
        __validators__={'complete_research_inventory':complete_research_inventory},
        research_step_ids=(list[item],field))
