"""Explicit immutable-preview roots. Configuration is not spending authority."""
from pathlib import Path
from urllib.parse import urlsplit
from hashlib import sha256
import json,os,sys,stat
from .services import digest
from .live_contracts import LiveResearchError

CODE_ROOT=Path(__file__).resolve().parents[1]
FIELDS={'project_root','code_root','application_root','legacy_root','canonical_ledger','runtime_origin','mode','live_enabled'}
ENV_PATH='VM_RUNTIME_CONFIGURATION'
ENV_HASH='VM_RUNTIME_CONFIGURATION_SHA256'
_INITIAL=(os.environ.get(ENV_PATH),os.environ.get(ENV_HASH))

def _absolute(value):
    if not isinstance(value,str) or not value or not Path(value).is_absolute():
        raise LiveResearchError('Runtime roots must be explicit absolute paths.')
    raw=Path(value)
    # Inspect every existing ancestor BEFORE resolve can hide a junction/alias.
    for part in (raw,*raw.parents):
        try:info=part.lstat()
        except FileNotFoundError:continue
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise LiveResearchError('Runtime root/ledger reparse alias refused.')
    return raw.resolve()

def validate_configuration(value):
    if not isinstance(value,dict) or set(value)!=FIELDS or value['mode']!='existing-only' or type(value['live_enabled']) is not bool:
        raise LiveResearchError('Unsupported immutable runtime configuration.')
    result=dict(value)
    for key in ('project_root','code_root','application_root','legacy_root','canonical_ledger'):
        result[key]=str(_absolute(value[key]))
    project=Path(result['project_root']);code=Path(result['code_root']);app=Path(result['application_root']);legacy=Path(result['legacy_root']);ledger=Path(result['canonical_ledger'])
    if code!=CODE_ROOT or code.is_relative_to(project) or project.is_relative_to(code) or not project.is_dir() or not code.is_dir():
        raise LiveResearchError('Runtime code/project root binding mismatch.')
    if ledger!=(project/'artifacts/m7-campaign-20261104/campaign.sqlite3').resolve() or not ledger.is_file():
        raise LiveResearchError('Existing canonical M7 campaign required; no creation or fallback.')
    if app==legacy or app.is_relative_to(code) or legacy.is_relative_to(code) or app.is_relative_to(project) or legacy.is_relative_to(project) or app.is_relative_to(legacy) or legacy.is_relative_to(app) or code.is_relative_to(app) or project.is_relative_to(app) or code.is_relative_to(legacy) or project.is_relative_to(legacy):
        raise LiveResearchError('Preview state must be separate from immutable code and project roots.')
    if not isinstance(value['runtime_origin'],str):raise LiveResearchError('Invalid preview origin type.')
    origin=urlsplit(value['runtime_origin'])
    try:port=origin.port
    except ValueError:raise LiveResearchError('Invalid preview origin.') from None
    if origin.scheme!='http' or origin.hostname!='127.0.0.1' or port is None or not 1024<=port<=65535 or port in (8501,8502) or origin.path or origin.query or origin.fragment or origin.username or value['runtime_origin']!=f'http://127.0.0.1:{port}':
        raise LiveResearchError('Bind an exact loopback preview origin.')
    for key,env in (('application_root','VM_APPLICATION_ROOT'),('legacy_root','VM_DEMO_ROOT')):
        if os.environ.get(env) and Path(os.environ[env]).resolve()!=Path(result[key]):
            raise LiveResearchError('Runtime state environment differs from configured preview roots.')
    for name,module in tuple(sys.modules.items()):
        if name=='vulnmgmt' or name.startswith('vulnmgmt.'):
            file=getattr(module,'__file__',None)
            if file and not Path(file).resolve().is_relative_to(code):
                raise LiveResearchError('Foreign/preloaded application module in bound preview.')
    return result

def _load():
    path,expected=_INITIAL
    if not path and not expected:return None,None
    if not path or not expected:raise LiveResearchError('Both runtime configuration file and canonical configuration SHA are required.')
    file=_absolute(path)
    if not file.is_file():raise LiveResearchError('Runtime configuration file unavailable.')
    raw=file.read_bytes()
    try:value=json.loads(raw)
    except (ValueError,UnicodeError):raise LiveResearchError('Invalid runtime configuration JSON.') from None
    result=validate_configuration(value)
    if digest(result)!=expected:raise LiveResearchError('Runtime configuration SHA mismatch.')
    return result,sha256(raw).hexdigest()

_CONFIG,_RAW_SHA=_load()

def runtime_configuration():
    if (os.environ.get(ENV_PATH),os.environ.get(ENV_HASH))!=_INITIAL:
        raise LiveResearchError('Runtime binding changed inside this process; start a new reviewed runtime.')
    if _CONFIG is not None:
        if sha256(Path(_INITIAL[0]).read_bytes()).hexdigest()!=_RAW_SHA:
            raise LiveResearchError('Immutable runtime configuration changed.')
        return validate_configuration(dict(_CONFIG))
    return dict(project_root=str(CODE_ROOT),code_root=str(CODE_ROOT),application_root=str(Path(os.environ.get('VM_APPLICATION_ROOT','artifacts/application')).resolve()),legacy_root=str(Path(os.environ.get('VM_DEMO_ROOT','artifacts/dashboard')).resolve()),canonical_ledger=str(CODE_ROOT/'artifacts/m7-campaign-20261104/campaign.sqlite3'),runtime_origin=None,mode='local-default',live_enabled=False)

def bound():return runtime_configuration()['mode']=='existing-only'

def require_live(version=''):
    raise LiveResearchError('Provider execution is disabled in the migration package; no spending authority was transferred.')
    config=runtime_configuration()
    if config['mode']=='existing-only':
        if not config['live_enabled']:raise LiveResearchError('Live AI is held in this review preview; Replay remains available.')
        if version not in {'m7-agent0-authorization','m7-agent0-permission','m7-agent2-v1','m7-agent3-v1','m7-agent4-v1','m7-agent6-v1','m7-agent7-v1'}:
            raise LiveResearchError('Retired live evaluation routes cannot create preview-local allowances; use the canonical M7 workflow.')

def validate_campaign(path):
    config=runtime_configuration()
    if config['mode']!='existing-only':return
    if Path(path).resolve()!=Path(config['canonical_ledger']):raise LiveResearchError('Canonical runtime campaign mismatch.')
    from . import m7_budget
    policy,_=m7_budget.snapshot(path,verify_sources=True)
    if policy['migrated']:
        import sqlite3
        with sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True) as c:
            project=c.execute('SELECT project_root FROM m7_schema_extensions').fetchone()[0]
        if Path(project).resolve()!=Path(config['project_root']):raise LiveResearchError('Canonical historical inventory root mismatch.')
    elif config['live_enabled']:
        raise LiveResearchError('Live preview requires explicitly installed canonical cumulative policy; startup never installs it.')


def historical_dashboard_root():
    """Historical projection stays at the canonical project, never preview code."""
    return Path(runtime_configuration()['project_root'])/'artifacts/dashboard-closeout-20261104-a/preserved-original'
