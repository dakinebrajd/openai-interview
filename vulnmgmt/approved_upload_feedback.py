"""Read-only upload feedback; scanner payloads and identity rules stay untouched."""
from .services import digest
from .live_contracts import redact


def upload_scope(manager, data):
    return digest([str(manager.root), data['workspace_id'], data['workspace_identity'], data['generation']])


def uploader_key(manager, data):
    return 'approved_files_' + upload_scope(manager, data)


def quarantine_rows(data):
    batches = {r['id']: r for r in data['ingestion_batches']}
    def safe(value):
        return redact(str(value))[:300] if value is not None else 'Not recorded'
    result = []
    for row in data['quarantine']:
        batch = batches.get(row['batch_id'], {})
        for issue in row['errors']:
            result.append(dict(scanner=safe(batch.get('scanner')), scan=safe(batch.get('native_scan_id')),
                               source_row=safe(row.get('native_finding_id')), code=safe(issue.get('code')),
                               field=safe(issue.get('field')), reason=safe(issue.get('message'))))
    return result


def receipt_summary(manager, data, receipt):
    if not isinstance(receipt, dict) or receipt.get('scope') != upload_scope(manager, data):
        return None
    ids = receipt.get('batch_ids')
    if not isinstance(ids, list) or not ids or any(not isinstance(id, str) for id in ids):
        return None
    if any(type(receipt.get(k)) is not int or receipt[k] < 0 for k in ('files','new_rows','repeated')):
        return None
    known = {r['id'] for r in data['ingestion_batches']}
    if not set(ids) <= known or receipt['files'] != len(ids) or receipt['repeated'] > receipt['files']:
        return None
    if receipt['new_rows'] > sum(r['ingestion_batch_id'] in ids for r in data['raw_findings']):
        return None
    batches = set(receipt['batch_ids'])
    quarantined = sum(r['batch_id'] in batches for r in data['quarantine'])
    text = (f"{receipt['files']} files processed: {receipt['new_rows']} new observations retained; "
            f"{receipt['repeated']} unchanged exports already retained. "
            f"{quarantined} quarantined observations in these exports.")
    return ('warning' if quarantined else 'success'), text
