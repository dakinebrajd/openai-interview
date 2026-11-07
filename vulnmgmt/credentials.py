"""Shared Windows Credential Manager access; never reads/export secrets via environment.

The Windows user is the security boundary, not the Python caller. No real store
operation occurs on import. Only explicitly confirmed execution resolves a key.
"""
import argparse
import ctypes
from ctypes import wintypes
import getpass
import re
import sys
import warnings
from pydantic import SecretStr
from .live_contracts import LiveResearchError

TARGET = 'VulnerabilityManagement/OpenAI/project-v1'
CRED_TYPE_GENERIC = 1
CRED_PERSIST_LOCAL_MACHINE = 2  # persists for this user on this computer
ERROR_NOT_FOUND = 1168


class CredentialError(LiveResearchError):
    pass


class _Credential(ctypes.Structure):
    _fields_ = [('Flags', wintypes.DWORD), ('Type', wintypes.DWORD),
        ('TargetName', wintypes.LPWSTR), ('Comment', wintypes.LPWSTR),
        ('LastWritten', wintypes.FILETIME), ('CredentialBlobSize', wintypes.DWORD),
        ('CredentialBlob', ctypes.POINTER(ctypes.c_ubyte)), ('Persist', wintypes.DWORD),
        ('AttributeCount', wintypes.DWORD), ('Attributes', ctypes.c_void_p),
        ('TargetAlias', wintypes.LPWSTR), ('UserName', wintypes.LPWSTR)]


def _validated(value):
    # Syntax/safety only; no authentication or provider access is inferred.
    if not isinstance(value, str) or not re.fullmatch(r'sk-[A-Za-z0-9_-]{20,512}', value):
        raise CredentialError('Credential format rejected; enter a replacement project API key privately.')
    return value


def _windows_api():
    raise CredentialError('Credential access is disabled in the migration package.')
    if sys.platform != 'win32':
        raise CredentialError('Windows Credential Manager requires Windows; no plaintext fallback is available.')
    try:
        api = ctypes.WinDLL('advapi32', use_last_error=True)
        api.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                 ctypes.POINTER(ctypes.POINTER(_Credential))]
        api.CredReadW.restype = wintypes.BOOL
        api.CredWriteW.argtypes = [ctypes.POINTER(_Credential), wintypes.DWORD]
        api.CredWriteW.restype = wintypes.BOOL
        api.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        api.CredDeleteW.restype = wintypes.BOOL
        api.CredFree.argtypes = [ctypes.c_void_p]
        api.CredFree.restype = None
        return api
    except OSError:
        raise CredentialError('Windows credential service is unavailable; no fallback was used.') from None


class WindowsCredentialStore:
    """Fixed dedicated target; no configurable paths, project IDs or secret cache."""
    def __init__(self,*,dummy_target=None):
        if dummy_target is not None and not re.fullmatch(r'VulnerabilityManagement/OfflineCredentialTest/[0-9a-f-]{36}',dummy_target):
            raise CredentialError('Only a generated isolated dummy target is permitted')
        self.target=dummy_target or TARGET
    def read(self):
        api = _windows_api()
        pointer = ctypes.POINTER(_Credential)()
        if not api.CredReadW(self.target, CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)):
            if ctypes.get_last_error() == ERROR_NOT_FOUND:
                raise CredentialError('Replacement credential is missing from Windows Credential Manager.')
            raise CredentialError('Windows credential retrieval failed; no fallback was used.')
        try:
            record = pointer.contents
            if not record.CredentialBlob or not 1 <= record.CredentialBlobSize <= 1024:
                raise CredentialError('Stored credential is invalid; replace it privately.')
            try:
                value = ctypes.string_at(record.CredentialBlob, record.CredentialBlobSize).decode('ascii')
            except UnicodeError:
                raise CredentialError('Stored credential encoding is invalid; replace it privately.') from None
            return SecretStr(_validated(value))
        finally:
            if pointer:
                # Clear our returned OS allocation before freeing it, never the store.
                record = pointer.contents
                if record.CredentialBlob and 0 < record.CredentialBlobSize <= 1024:
                    ctypes.memset(record.CredentialBlob, 0, record.CredentialBlobSize)
                api.CredFree(pointer)

    def write(self, value):
        key = _validated(value.get_secret_value())
        api = _windows_api()
        blob = ctypes.create_string_buffer(key.encode('ascii'))
        record = _Credential(Type=CRED_TYPE_GENERIC, TargetName=self.target,
            CredentialBlobSize=len(key), CredentialBlob=ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte)),
            Persist=CRED_PERSIST_LOCAL_MACHINE, UserName='OpenAI dedicated project credential')
        try:
            if not api.CredWriteW(ctypes.byref(record), 0):
                raise CredentialError('Windows credential storage failed; no fallback was used.')
        finally:
            ctypes.memset(blob, 0, ctypes.sizeof(blob))

    def remove(self):
        api = _windows_api()
        if not api.CredDeleteW(self.target, CRED_TYPE_GENERIC, 0) and ctypes.get_last_error() != ERROR_NOT_FOUND:
            raise CredentialError('Windows credential removal failed.')


def for_operation(config, *, confirmed, store=None):
    """Return a short-lived secret-bearing copy, only after independent policy gates.

    Callers must separately validate their operation/revision/lease and reserve cost.
    No cache: the next operation observes rotation. Never export the result to env/UI.
    """
    raise CredentialError('Credential access is disabled in the migration package.')
    config.require_authorization()
    if not confirmed:
        raise CredentialError('Explicit operation confirmation is required before credential access.')
    key = (store or WindowsCredentialStore()).read()
    _validated(key.get_secret_value())
    return config.model_copy(update={'api_key': key})


def main(argv=None):
    parser = argparse.ArgumentParser(description='Private Windows project credential setup/rotation/removal. No API calls.')
    parser.add_argument('action', choices=('setup', 'rotate', 'remove'))
    parser.add_argument('--confirm-store', action='store_true')
    parser.add_argument('--confirm-remove', action='store_true')
    args = parser.parse_args(argv)
    store = WindowsCredentialStore()
    if args.action == 'remove':
        if not args.confirm_remove:
            parser.error('Removal requires --confirm-remove.')
        store.remove()
        print('Local project credential removed (or already absent). Provider revocation is separate.')
        return 0
    if not args.confirm_store or not sys.stdin.isatty():
        parser.error('Setup/rotation requires --confirm-store and a private interactive terminal; piping is refused.')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            first = getpass.getpass('Replacement project API key (hidden): ')
            second = getpass.getpass('Repeat replacement key (hidden): ')
        if first != second:
            raise CredentialError('Credential entries did not match; nothing was stored.')
        store.write(SecretStr(_validated(first)))
    except (getpass.GetPassWarning, EOFError, KeyboardInterrupt):
        raise CredentialError('Hidden credential input unavailable or cancelled; nothing was stored.') from None
    finally:
        # Python/SDK strings cannot promise secure memory erasure; never persist them.
        first = second = None
    print('Replacement stored in Windows Credential Manager. Live execution remains separately gated.')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except CredentialError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
