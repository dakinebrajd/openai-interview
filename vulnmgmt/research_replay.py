"""Conservative Agent 2 replay through the existing research and review service."""
import json
from dataclasses import dataclass
from . import live_research,live_evidence
from .live_contracts import Agent2Result,LiveConfig

class Replay:
    origin='human_curated_source_backed_replay'
    def run(self,config,prompt):
        s=json.loads(prompt)
        unknown=dict(value=None,status='Unknown',evidence=[],interpretation='Unknown; review captured authoritative evidence.')
        claim=unknown
        instruction=s.get('curated_vendor_instruction')
        for source in s['sources']:
            if source['kind']=='Vendor' and instruction and instruction in source['text']:
                # Copy the CVE-bound curated instruction, never an arbitrary
                # advisory prefix that might describe a neighboring issue.
                text=instruction
                if '...' not in text and '\u2026' not in text:
                    claim=dict(value=text,status='Supported',evidence=[dict(source_id=source['id'],excerpt=text)],
                        interpretation='Historical vendor evidence only; current target and actual applicability remain unknown.')
                    break
        r=dict(cve_id=s['cve_id'],**{k:unknown for k in ('description','affected_product','affected_versions','advisory_identifiers')},
            vendor_remediation=claim,applicability='Synthetic assumption' if s['synthetic_assumptions'] else 'Unknown',
            synthetic_assumptions=s['synthetic_assumptions'],conflicting_or_missing_evidence=s['source_limitations'],
            analyst_validation=['Review historical vendor context, current supported target and synthetic inventory assumptions.'],
            execution_status='Proposed; analyst review required')
        return dict(candidate=r,origin=self.origin,provider_attempts=0,usage=None,model_requested='source-backed-replay',
            model_served=None,response_ids=[],request_ids=[])

@dataclass(frozen=True)
class Spec:
    role:int=2
    version:str='m6f-agent2-replay-v1'
    mode:str='replay'
    result_key:str='agent2-replay-result'
    events:str='Agent2ReplayResearch'
    instructions:str='Review dated source facts; this is human-curated replay, not model execution.'
    output_type:type=Agent2Result
    @staticmethod
    def context(data,cve,secret=''):
        supplied=live_evidence.context(data,cve,secret)
        guidance=[json.loads(s['output_json'])['guidance'] for s in data['agent_steps']
            if s['role_number']==2 and s['step_key']==cve and s['output_json'] and 'guidance' in json.loads(s['output_json'])]
        instructions={g['instructions'] for g in guidance if g['status']=='Supported' and g['instructions']}
        supplied['curated_vendor_instruction']=next(iter(instructions)) if len(instructions)==1 and not supplied['historical_guidance_conflict'] else None
        return dict(supplied,as_of=data['as_of'])
    validate=staticmethod(live_evidence.validate)
    assess=staticmethod(live_evidence.assess)
    from .dashboard_queries import revision_token as review_token
    review_token=staticmethod(review_token)

def run(manager,generation,**request):
    return live_research.run(manager,generation,config=LiveConfig(model='source-backed-replay',session_id='agent0-replay'),
        gateway=Replay(),spec=Spec(),**request)

def review(manager,generation,**request):return live_research.review(manager,generation,spec=Spec(),**request)
