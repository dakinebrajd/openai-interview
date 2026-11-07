"""Explicit nonbillable negative control, implemented through the shared SDK."""
import json
import httpx2
from pydantic import SecretStr
from .agent2_sdk import SDKAgent2
from .live_contracts import LiveConfig
from .application import MODEL
from .research_replay import Replay

def unsupported_adapter(state):
    def respond(request):
        body=json.loads(request.content);prompt=next(i['content'] for i in body['input'] if i['role']=='user')
        candidate=Replay().run(None,prompt)['candidate']
        candidate['vendor_remediation']=dict(status='Supported',value='Invented patch claim',
            evidence=[dict(source_id='FABRICATED-SOURCE',excerpt='Invented patch claim')],interpretation='OFFLINE NEGATIVE CONTROL; deliberately unsupported')
        return httpx2.Response(200,json=dict(id='resp_offline_negative_control',object='response',created_at=1,status='completed',model=MODEL,
            error=None,incomplete_details=None,output=[dict(id='msg_offline_negative_control',type='message',status='completed',role='assistant',
                content=[dict(type='output_text',text=json.dumps(candidate),annotations=[])])],usage=dict(input_tokens=800,output_tokens=250,total_tokens=1050)))
    return dict(config=LiveConfig(enabled=True,authorized=True,model=MODEL,session_id='m7-offline-negative',api_key=SecretStr('OFFLINE-ONLY-FAKE'),
        budget_usd=.1,input_rate=.75,output_rate=4.5),gateway=SDKAgent2(test_transport=httpx2.MockTransport(respond)))
