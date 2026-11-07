"""SDK-only Agent 6 output references; persisted contracts remain unchanged."""
from typing import Annotated
from pydantic import Field,model_validator
from .drafting_contracts import Composition,Agent6Result


class SDKComposition(Composition):
    interpretation_indices: list[Annotated[int,Field(ge=0,le=7)]] = Field(max_length=8,
        description='Unique zero-based positions in the OUTPUT interpretations array, NOT input facts or fact_order. For three output interpretations use only 0, 1, 2. Use an empty list when none apply. Every index must be smaller than the emitted interpretations length.')


class Agent6SDKResult(Agent6Result):
    consolidated_report: SDKComposition
    ticket_description: SDKComposition
    synthetic_email: SDKComposition

    @model_validator(mode='after')
    def valid_output_references(self):
        for composition in (self.consolidated_report,self.ticket_description,self.synthetic_email):
            indices=composition.interpretation_indices
            if len(set(indices))!=len(indices) or any(not 0<=index<len(self.interpretations) for index in indices):
                raise ValueError('Interpretation references must be unique zero-based positions in the emitted output interpretations array.')
        return self  # Validate only: never repair, filter, renumber or pad output.
