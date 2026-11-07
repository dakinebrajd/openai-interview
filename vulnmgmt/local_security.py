"""Fail-closed local-only credential UI boundary. No proxy/remote secret setup."""
import sys,ctypes,os
from urllib.parse import urlsplit
from .credentials import CredentialError

def validate_local_binding(address,url,headers,platform,interactive):
    if platform!='win32' or not interactive:raise CredentialError('Credential management requires an interactive Windows user security context')
    if address not in ('127.0.0.1','::1'):raise CredentialError('Bind the application explicitly to 127.0.0.1; wildcard and remote exposure are refused')
    u=urlsplit(url or '')
    if u.scheme not in ('http','https') or u.hostname not in ('127.0.0.1','localhost','::1'):raise CredentialError('Only a direct local browser connection can manage credentials')
    lower={k.lower():v for k,v in headers.items()}
    if any(k in lower for k in ('forwarded','x-forwarded-for','x-forwarded-host','x-real-ip')):raise CredentialError('Proxy-forwarded credential access is refused')
    origin=lower.get('origin')
    if origin and urlsplit(origin).netloc!=u.netloc:raise CredentialError('Cross-origin credential access refused')
    return True

def require_local_operator():
    import streamlit as st
    interactive=False
    if sys.platform=='win32':
        session=ctypes.c_ulong()
        interactive=bool(ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(),ctypes.byref(session))) and session.value!=0
    return validate_local_binding(st.get_option('server.address'),st.context.url,dict(st.context.headers),sys.platform,interactive)

def credential_action(action,*,confirmed,value=None,repeat=None,store=None):
    require_local_operator()
    if not confirmed:raise CredentialError('Explicit credential operation confirmation required')
    from .credentials import WindowsCredentialStore,_validated
    from pydantic import SecretStr
    provider=store or WindowsCredentialStore()
    if action=='store':
        if value!=repeat:raise CredentialError('Credential entries do not match; nothing stored')
        provider.write(SecretStr(_validated(value)))
        if provider.read().get_secret_value()!=value:raise CredentialError('Secure storage verification failed')
        return 'Stored and retrieved securely; value withheld. Live spending remains separately gated.'
    if action=='remove':provider.remove();return 'Local credential removed. Provider-side revocation is separate.'
    if action=='status':
        provider.read();return 'Credential available in this Windows account; value withheld. No model request made.'
    raise CredentialError('Unknown credential action')

def dummy_roundtrip():
    require_local_operator()
    from .credentials import WindowsCredentialStore
    from .live_contracts import redact
    from uuid import uuid4
    from pydantic import SecretStr
    store=WindowsCredentialStore(dummy_target='VulnerabilityManagement/OfflineCredentialTest/'+str(uuid4()))
    def missing():
        try:store.read()
        except CredentialError as exc:
            if 'missing' in str(exc):return True
            raise
        return False
    if not missing():raise CredentialError('Dummy target unexpectedly exists; nothing changed')
    try:
        a=SecretStr('sk-OFFLINE_DUMMY_'+uuid4().hex);b=SecretStr('sk-OFFLINE_DUMMY_'+uuid4().hex)
        store.write(a);assert store.read().get_secret_value()==a.get_secret_value()
        store.write(b);assert store.read().get_secret_value()==b.get_secret_value()
        assert redact(b.get_secret_value())=='[REDACTED]'
        store.remove();assert missing()
        return dict(status='Pass',retrieval=True,rotation=True,deletion=True,missing=True,redaction=True,production_target_accessed=False)
    finally:store.remove()
