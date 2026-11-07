"""Agent 2 boundary: quoted vendor facts, explicitly unverified interpretation."""
import os
import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from .contracts import CVE


class LiveResearchError(ValueError):
    """Only deliberately safe messages cross the dashboard/lease boundary."""


class EvidenceValidationError(LiveResearchError):
    """Sanitized field/category diagnostics; never copy rejected input into errors."""
    def __init__(self, assessment):
        self.assessment = assessment
        failures = [d for d in assessment['diagnostics'] if d['result'] == 'Fail']
        super().__init__('; '.join(d['field']+': '+d['category'] for d in failures))


class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, allow_inf_nan=False)


class EvidenceQuote(Strict):
    source_id: str = Field(min_length=1, max_length=100)
    excerpt: str = Field(min_length=1, max_length=2000,
        description='Exact contiguous captured text. No ellipses, stitching, or edits. Use separate quotes for separate passages.')


class ResearchClaim(Strict):
    value: str | None = Field(max_length=2000,
        description='Source quotation, or conservatively extracted product name/affected version range. Never a free paraphrase. Unknown uses null.')
    status: Literal['Supported', 'Unknown', 'Conflicting Evidence']
    evidence: list[EvidenceQuote] = Field(max_length=8)
    interpretation: str = Field(max_length=1000, description='Unverified model interpretation, not a vendor quotation')


class Agent2Result(Strict):
    cve_id: CVE
    description: ResearchClaim
    affected_product: ResearchClaim
    affected_versions: ResearchClaim
    vendor_remediation: ResearchClaim
    advisory_identifiers: ResearchClaim
    applicability: Literal['Unknown', 'Synthetic assumption', 'Conflicting Evidence']
    synthetic_assumptions: list[str] = Field(max_length=10)
    conflicting_or_missing_evidence: list[str] = Field(max_length=20)
    analyst_validation: list[str] = Field(min_length=1, max_length=12)
    execution_status: Literal['Proposed; analyst review required']


class LiveConfig(Strict):
    enabled: bool = False
    authorized: bool = False
    model: str = ''
    session_id: str = ''
    api_key: SecretStr = Field(default_factory=lambda: SecretStr(''), repr=False, exclude=True)
    allow_public_fetch: bool = False
    max_output_tokens: int = Field(default=4096, ge=512, le=8192)
    max_input_bytes: int = Field(default=60000, ge=1000, le=120000)
    max_session_requests: int = Field(default=1, ge=1, le=10)
    session_output_tokens: int = Field(default=4096, ge=512, le=81920)
    budget_usd: float = Field(default=0.0, ge=0, le=10)
    input_rate: float = Field(default=0.0, ge=0, le=100)
    output_rate: float = Field(default=0.0, ge=0, le=1000)
    timeout_seconds: float = Field(default=60.0, ge=1, le=120)

    @classmethod
    def environment(cls):
        """Read non-secret policy settings only; ignore inherited API credentials."""
        env = os.environ
        try:
            return cls(enabled=env.get('VM_LIVE_ENABLED') == '1',
                authorized=env.get('VM_LIVE_AUTHORIZED') == '1',
                model=env.get('VM_LIVE_MODEL', ''), session_id=env.get('VM_LIVE_SESSION_ID', ''),
                allow_public_fetch=env.get('VM_LIVE_ALLOW_PUBLIC_FETCH') == '1',
                **{field: cast(env.get(name, str(default))) for field, name, cast, default in (
                    ('max_output_tokens', 'VM_LIVE_MAX_OUTPUT_TOKENS', int, 4096),
                    ('max_input_bytes', 'VM_LIVE_MAX_INPUT_BYTES', int, 60000),
                    ('max_session_requests', 'VM_LIVE_MAX_SESSION_REQUESTS', int, 1),
                    ('session_output_tokens', 'VM_LIVE_SESSION_OUTPUT_TOKENS', int, 4096),
                    ('budget_usd', 'VM_LIVE_BUDGET_USD', float, 0),
                    ('input_rate', 'VM_LIVE_INPUT_RATE', float, 0),
                    ('output_rate', 'VM_LIVE_OUTPUT_RATE', float, 0),
                    ('timeout_seconds', 'VM_LIVE_TIMEOUT_SECONDS', float, 60))})
        except ValueError:
            raise LiveResearchError('Invalid live configuration; check non-secret limits.') from None

    def require(self):
        self.require_authorization()
        if not self.api_key.get_secret_value().strip():
            raise LiveResearchError('Runtime credential is missing. Configure a replacement privately in Windows Credential Manager.')

    def require_authorization(self):
        """Credential possession is never execution authorization; no secret lookup."""
        if not self.enabled:
            raise LiveResearchError('Live AI is disabled. Evidence replay remains available.')
        if not self.authorized:
            raise LiveResearchError('Live execution requires explicit model, budget and execution authorization.')
        if (not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,80}', self.model)
                or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', self.session_id)
                or 'sk-' in self.model or 'sk-' in self.session_id):
            raise LiveResearchError('Configure a non-secret model identifier and approved session identifier.')
        if not self.budget_usd or not self.input_rate or not self.output_rate:
            raise LiveResearchError('Positive approved budget and current input/output price estimates are required.')


SECRET_PATTERN = re.compile(r'(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{12,}')


def redact(value, secret=''):
    """Defense against model/error echo; never persist raw provider exceptions."""
    if isinstance(value, str):
        if secret:
            value = value.replace(secret, '[REDACTED]')
        return SECRET_PATTERN.sub('[REDACTED]', value)
    if isinstance(value, dict):
        return {redact(k, secret): redact(v, secret) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secret) for v in value]
    return value


def provider_diagnostics(error, secret, stage):
    """Allowlisted SDK scalar metadata only: never exception bodies or headers."""
    def identifier(value, *, request=False):
        if not isinstance(value, str) or redact(value, secret) != value:
            return None
        pattern = r'req_[A-Za-z0-9_-]{1,120}' if request else r'[A-Za-z][A-Za-z0-9_.:-]{0,127}'
        return value if re.fullmatch(pattern, value) else None
    status = getattr(error, 'status_code', None)
    return dict(failure_stage=stage, exception_class=identifier(type(error).__name__),
        http_status=status if type(status) is int and 100 <= status <= 599 else None,
        provider_error_code=identifier(getattr(error, 'code', None)),
        provider_error_type=identifier(getattr(error, 'type', None)),
        provider_request_id=identifier(getattr(error, 'request_id', None), request=True))


def execution_summary(payload):
    """Separate provider transport/structured response from local acceptance, including v1 records."""
    execution = payload['execution']
    diagnostic = execution.get('failure_diagnostics', {})
    structured = bool(payload.get('quarantined_candidate') or payload.get('result'))
    return dict(provider_status='Offline mock; no provider call' if execution.get('origin') == 'offline_mock' else
                'Successful structured response' if structured else
                'HTTP 200; structured response unavailable' if diagnostic.get('http_status') == 200 else
                'Failed or unavailable; inspect recorded diagnostics',
                structured_output_available=structured,
                research_status='Proposed; analyst review required' if payload.get('result') else 'Rejected/quarantined',
                failed_stage=diagnostic.get('failure_stage'))
