"""Exact demo recognition; ordinary scanner validation remains unchanged."""
from . import two_resolver_demo as demo

NAMES=('tenable-a.json','tenable-b.json','defender-a.json','defender-b.json')
def prepare_known_set(manager,data,files):
    if len(files)!=len(NAMES) or {name for name,content in files}!=set(NAMES):return False
    directories=(demo.DIRECTORY,demo.DIRECTORY.parent/'v3')
    matched=next((directory for directory in directories if all((directory/name).is_file() and content==(directory/name).read_bytes() for name,content in files)),None)
    if matched is None:return False
    if not any(e['event_type']==demo.EVENT for e in data['audit_events']):
        demo.prepare(manager,data['generation'],confirmed=True,actor='local-analyst',reason='User uploaded the complete exact versioned four-file synthetic demo')
    return True
