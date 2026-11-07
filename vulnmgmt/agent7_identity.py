"""Request-local Agent 7 output identity constraints; no repair or action authority."""
from copy import deepcopy
from typing import Literal
from uuid import UUID
from pydantic import create_model, model_validator, Field
from .reply_contracts import ReplyInput, Agent7Result
from .live_contracts import LiveResearchError
from .services import digest

IDENTITY_FIELDS=('workspace_id','reply_id','ticket_id','ticket_revision','owner_id','communication_id','body_hash')


def bound_agent7_output(supplied):
    s=ReplyInput.model_validate(supplied)
    expected={name:getattr(s,name) for name in IDENTITY_FIELDS}
    ids=tuple(s.finding_ids)
    for name in ('workspace_id','reply_id','ticket_id','owner_id','communication_id'):
        value=expected[name]
        if name=='communication_id' and value is None:
            continue
        try:valid=isinstance(value,str) and str(UUID(value))==value
        except (ValueError,TypeError,AttributeError):valid=False
        if not valid:
            raise LiveResearchError('Agent 7 requires canonical supplied identity UUIDs.')
    if (s.ticket_revision<0 or digest(s.body)!=s.body_hash or not ids or len(ids)>1000
            or len(set(ids))!=len(ids)):
        raise LiveResearchError('Agent 7 requires intact reply content and bounded unique finding identities.')
    for value in ids:
        try:valid=isinstance(value,str) and str(UUID(value))==value
        except (ValueError,TypeError,AttributeError):valid=False
        if not valid:
            raise LiveResearchError('Agent 7 requires canonical supplied finding UUIDs.')
    fields={}
    for name,value in expected.items():
        field=deepcopy(Agent7Result.model_fields[name])
        field.description='Exact request-bound supplied '+name+'. Copy this constant unchanged; never calculate, summarize or substitute it.'
        fields[name]=(Literal[value],field)
    field=Field(min_length=len(ids),max_length=len(ids))
    field.description='Copy the complete supplied finding_ids array once each, in its original order. This is an identity binding, not a selection.'
    fields['finding_ids']=(list[Literal[ids]],field)

    @model_validator(mode='before')
    def exact_identity(cls,value):
        if isinstance(value,dict):
            for name,expected_value in expected.items():
                actual=value.get(name)
                if type(actual) is not type(expected_value) or actual!=expected_value:
                    raise ValueError('Agent 7 output identity differs from its supplied request.')
            if value.get('finding_ids')!=list(ids):
                raise ValueError('Agent 7 output finding identities must exactly match supplied order and membership.')
        return value  # Validate only; never rewrite a candidate or its identity.

    output=create_model('RequestBoundAgent7Result',__base__=Agent7Result,
                        __validators__={'exact_identity':exact_identity},**fields)
    enums=[]
    def collect(value):
        if isinstance(value,dict):
            if 'enum' in value:enums.append(value['enum'])
            for child in value.values():collect(child)
        elif isinstance(value,list):
            for child in value:collect(child)
    collect(output.model_json_schema())
    if sum(len(values) for values in enums)>1000 or any(
            len(values)>250 and sum(len(v) for v in values if isinstance(v,str))>15000 for values in enums):
        raise LiveResearchError('Agent 7 identity schema exceeds supported enum bounds.')
    return output
