"""Explicit additive synthetic inventory, before importing any observations."""
import json
from pathlib import Path
from hashlib import sha256
from sqlalchemy import select
from .database import make_engine,tables
from .services import stable,audit,canonical,digest

DIRECTORY=Path(__file__).resolve().parents[1]/'fixtures/workflow_demo/v2'
EVENT='TwoResolverDemoInventoryPrepared'

def fixture():
    manifest=json.loads((DIRECTORY/'manifest.json').read_text(encoding='utf-8'))
    if sha256((DIRECTORY/'enrichment/manifest.json').read_bytes()).hexdigest()!=manifest['enrichment_manifest_sha256']:
        raise ValueError('Two resolver retained enrichment manifest checksum mismatch')
    for name,expected in manifest['files'].items():
        if Path(name).name!=name or sha256((DIRECTORY/name).read_bytes()).hexdigest()!=expected:
            raise ValueError('Two resolver fixture checksum mismatch')
    return manifest,json.loads((DIRECTORY/'inventory.json').read_text(encoding='utf-8'))

def prepare(manager,generation,*,confirmed,actor,reason):
    if not confirmed or not actor.strip() or not reason.strip():
        raise ValueError('Confirm the synthetic inventory with a named analyst and rationale')
    manifest,inventory=fixture()
    with manager.execution(generation,'prepare_two_resolver_demo') as (path,w,clock,receipt):
        e=make_engine(path)
        try:
            with e.begin() as c:
                prior=c.execute(select(tables['audit_events']).where(tables['audit_events'].c.workspace_id==w['id'],tables['audit_events'].c.event_type==EVENT)).mappings().first()
                if prior:
                    payload=json.loads(prior['payload_json'])
                    if payload['fixture_hash']!=digest(manifest):raise ValueError('Prepared fixture changed; use a new assessment')
                    return dict(prepared=True,repeated=True,assets=2)
                if c.scalar(select(tables['asset_cves'].c.id).where(tables['asset_cves'].c.workspace_id==w['id'])):
                    raise ValueError('Prepare this demo in a fresh assessment before importing scanner files')
                for owner in inventory['owners']+inventory['resolver_groups']:
                    c.execute(tables['owners'].insert().values(id=stable(w['id'],'owner',owner['key']),workspace_id=w['id'],display_name=owner['name'],synthetic_email=owner['email']))
                for asset in inventory['assets']:
                    aid=stable(w['id'],'asset',asset['key'])
                    c.execute(tables['assets'].insert().values(id=aid,workspace_id=w['id'],asset_key=asset['key'],hostname=asset['hostname'],criticality=asset['criticality']))
                    for role,key in [('primary',asset['owner_key']),('secondary',asset['resolver_group'])]:
                        c.execute(tables['asset_owners'].insert().values(id=stable(w['id'],'ownership',asset['key'],role),workspace_id=w['id'],asset_id=aid,owner_id=stable(w['id'],'owner',key),role=role,valid_from=clock))
                    for scanner,native in asset['aliases'].items():
                        c.execute(tables['asset_aliases'].insert().values(id=stable(w['id'],'alias',scanner,native),workspace_id=w['id'],asset_id=aid,scanner=scanner,scanner_tenant='agency-demo',native_asset_id=native))
                    for component in asset['components']:
                        c.execute(tables['asset_components'].insert().values(id=stable(w['id'],'component',asset['key'],component['key']),workspace_id=w['id'],asset_id=aid,component_key=component['key'],product=component['product'],installed_version=None,location=component['location']))
                    audit(c,w['id'],'SyntheticInventoryAsset','assets',aid,0,dict(asset_type=asset['type'],resolver_group_key=asset['resolver_group']))
                audit(c,w['id'],EVENT,'demo_workspaces',w['id'],0,dict(fixture_hash=digest(manifest),actor=actor,reason=reason,synthetic=True,imports_executed=False),actor_type='analyst',actor_id=actor)
                return dict(prepared=True,repeated=False,assets=2)
        finally:e.dispose()

def replay_directory(connection,workspace):
    prepared=connection.scalar(select(tables['audit_events'].c.id).where(tables['audit_events'].c.workspace_id==workspace,tables['audit_events'].c.event_type==EVENT))
    if prepared:
        fixture()
        return DIRECTORY/'enrichment'
    return None

def retained_evidence(connection,workspace,clock):
    """Reuse this fixed demo's curated extraction, never rerun or reuse paid AI."""
    directory=replay_directory(connection,workspace)
    if directory is None:return None,None
    from .enrichment import load_bundle
    manifest,_,_=load_bundle(directory)
    observations=[dict(row) for row in connection.execute(select(tables['raw_findings']).where(tables['raw_findings'].c.workspace_id==workspace).order_by(tables['raw_findings'].c.id)).mappings()]
    components=[dict(row) for row in connection.execute(select(tables['asset_components']).where(tables['asset_components'].c.workspace_id==workspace).order_by(tables['asset_components'].c.id)).mappings()]
    key=digest(dict(manifest=manifest,observations=observations,components=components,clock=clock))
    for event in connection.execute(select(tables['audit_events']).where(tables['audit_events'].c.workspace_id==workspace,tables['audit_events'].c.event_type=='TwoResolverCuratedEvidencePrepared')).mappings():
        saved=json.loads(event['payload_json'])
        if saved['input_key']==key:
            return key,dict(saved['result'],linked_prior_curated_evidence=True,current_source_retrievals=0,real_model_calls=0)
    return key,None
