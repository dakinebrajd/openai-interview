"""Reviewed SDK wording selection; the existing arbitrary-prose gate is unchanged."""
from typing import Literal
from pydantic import Field
from .drafting_contracts import ConditionalInterpretation
from .agent6_references import Agent6SDKResult
from .services import digest

VERSION='agent6-predefined-prose-v1'
REASONING_TEMPLATES=(
    'The scoped findings can be reviewed together using the historical guidance. Actual applicability and a safe current target remain unknown; obtain a resolver plan before action.',
    'Shared historical guidance may support one resolver review, but actual applicability remains unknown. Keep source uncertainty visible before requesting a schedule.',
    'Current deployment target is unknown.',
    'Review the supplied exploitation evidence, its scope and observation dates.',
    'Actual applicability remains unknown.',
    'Source facts and uncertainty require analyst review. Current support and real applicability remain unverified.',
    'Owner assertions require review and subsequent independent scanner evidence.',
    'Historical guidance can inform planning; actual applicability and an appropriate current target remain unknown.',
    'Routing and hypothetical deadlines require separate analyst validation. This draft grants no authority to act.',
)
REVIEW_TEMPLATES=(
    'Review source context, inventory, platform support and the exact proposed content.',
    'Review routing, hypothetical deadlines and separate ticket and communication decisions.',
    'Review cited source context, inventory and platform support before choosing a target.',
    'Check source observation dates and distinguish historical evidence from current guidance.',
    'Verify the exact proposed content and obtain the required named analyst decisions.',
    'Require independent scanner evidence before recording a remediation outcome.',
)


class PredefinedConditionalInterpretation(ConditionalInterpretation):
    reasoning: Literal[REASONING_TEMPLATES]=Field(min_length=1,max_length=1200,
        description='Select one exact complete predefined wording template. No additions, prefixes, suffixes, quotation wrappers, paraphrase or punctuation changes. This is model-selected predefined wording, not free-form prose authorship.')


class Agent6PredefinedSDKResult(Agent6SDKResult):
    interpretations: list[PredefinedConditionalInterpretation]=Field(min_length=1,max_length=8)
    analyst_validation: list[Literal[REVIEW_TEMPLATES]]=Field(min_length=1,max_length=10,
        description='Select exact predefined analyst-request templates only. These requests grant no approval or operational authority.')


def catalog_metadata():
    catalog=dict(version=VERSION,reasoning_templates=list(REASONING_TEMPLATES),analyst_review_templates=list(REVIEW_TEMPLATES))
    return dict(catalog,catalog_sha256=digest(catalog),
        wording_origin='Model-selected predefined wording; not free-form model-authored prose',
        human_acceptance='Pending; offline tests and independent technical review are not human semantic acceptance',
        raw_provider_json_text_captured=False,
        candidate_recording='Existing typed model_candidate values when available; raw provider JSON is not captured. Schema/parse failures may have no candidate.',
        validation_policy='Existing arbitrary-prose unsafe gate and all evidence/identity/approval rules remain unchanged')
