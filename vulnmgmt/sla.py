"""Hypothetical agency calendar-hour SLA, not a binding policy or CISA deadline."""
from datetime import timedelta
from .enrichment_evidence import timestamp
from .services import utc

POLICY = {
    'key': 'hypothetical-agency-m4', 'version': 1,
    'label': 'HYPOTHETICAL AGENCY POLICY - DEMONSTRATION ONLY',
    'hours': {'Critical actively exploited': 24, 'Critical exploitable': 72,
              'Critical': 14*24, 'High': 30*24, 'Medium': 60*24, 'Low': 90*24, 'Informational': 90*24},
    'clock': 'Earliest validated scanner observation; no reset for reimport, new intelligence or scheduling',
    'exception': 'Approved, expiring deferment pauses effective overdue only; underlying due date and finding stay unchanged',
    'active_definition': 'Policy urgency trigger uses verified KEV/explicit exploitation evidence, not a claim of an active attack on this asset',
    'exploitable_definition': 'Explicit verified technical exploitability claim; EPSS alone is insufficient',
}


def calculate_sla(severity, first_seen, *, actively_exploited=False, exploitable=False, policy=POLICY):
    category = severity
    if severity == 'Critical':
        category = 'Critical actively exploited' if actively_exploited else 'Critical exploitable' if exploitable else 'Critical'
    hours = policy['hours'].get(category)
    return {'policy': policy['label'], 'policy_key': policy['key'], 'policy_version': policy['version'],
            'category': category, 'hours': hours, 'clock_start': utc(timestamp(first_seen)),
            'due_at': utc(timestamp(first_seen)+timedelta(hours=hours)) if hours is not None else None,
            'requires_review': hours is None}


def overdue_state(due_at, now, *, exception_until=None, verified=False):
    underlying = bool(due_at and timestamp(now) > timestamp(due_at) and not verified)
    deferred = bool(exception_until and timestamp(now) < timestamp(exception_until) and not verified)
    return {'underlying_overdue': underlying, 'exception_active': deferred,
            'overdue': underlying and not deferred, 'deadline': due_at, 'exception_until': exception_until}
