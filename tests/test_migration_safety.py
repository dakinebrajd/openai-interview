import subprocess
import sys
from pathlib import Path
import pytest
from vulnmgmt.runtime_binding import require_live, runtime_configuration
from vulnmgmt.live_contracts import LiveResearchError
from vulnmgmt.credentials import _windows_api, for_operation, CredentialError
from vulnmgmt.live_ui_policy import replay_only

@pytest.mark.parametrize("version", ["", "m7-agent0-authorization", "m7-agent0-permission", "m7-agent2-v1", "m7-agent3-v1", "m7-agent4-v1", "m7-agent6-v1", "m7-agent7-v1"])
def test_live_paths_denied(version):
    with pytest.raises(LiveResearchError, match="disabled"):
        require_live(version)

def test_default_live_disabled():
    assert runtime_configuration()["live_enabled"] is False
    assert replay_only()

def test_store_denied():
    with pytest.raises(CredentialError, match="disabled"):
        _windows_api()

def test_for_operation_denied_before_config_or_store():
    with pytest.raises(CredentialError, match="disabled"):
        for_operation(object(), confirmed=True, store=object())

def test_default_launcher_stops():
    result=subprocess.run([sys.executable,"-B","app.py"],cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True)
    assert result.returncode != 0
    assert "MIGRATION HOLD" in result.stderr
