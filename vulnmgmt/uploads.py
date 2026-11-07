"""Browser upload adapter/preview using the exact existing transactional importer."""
import csv,io,json
from .scanners import ingest_export,_unique_keys
from .database import make_engine,tables
from .services import canonical,digest
from .live_contracts import redact
from sqlalchemy import select

MAX_BYTES=8000000

def decode(content,name,selected='Auto detect'):
    if not content or len(content)>MAX_BYTES:raise ValueError('Choose a nonempty synthetic export up to 8 MB')
    if redact(name)!=name:raise ValueError('Secret-shaped filename refused')
    text=content.decode('utf-8-sig')
    if redact(text)!=text:raise ValueError('Secret-shaped content refused; only public/synthetic scanner data is permitted')
    if name.lower().endswith('.csv'):
        rows=list(csv.DictReader(io.StringIO(text)))
        if not rows:raise ValueError('CSV has no records')
        meta=('format','format_version','synthetic','tenant','scan_id','exported_at')
        if any(k not in rows[0] for k in meta):raise ValueError('Synthetic CSV requires format, format_version, synthetic, tenant, scan_id and exported_at columns; download a sample')
        if any(any(r[k]!=rows[0][k] for k in meta) for r in rows):raise ValueError('CSV export metadata must be identical on every row')
        first=rows[0]
        if first['synthetic'].lower()!='true' or first['format_version']!='1':raise ValueError('Only explicitly synthetic version-1 CSV is supported')
        fmt=first['format'];findings=[]
        for raw in rows:
            row={k:v for k,v in raw.items() if k not in meta}
            if fmt=='synthetic-tenable':
                row['cve']=row.get('cve','').split(';')
                try:row['severity']=int(row['severity'])
                except (ValueError,KeyError):pass # existing importer quarantines invalid rows
            findings.append(row)
        parsed=dict(format=fmt,format_version='1',synthetic=True)
        if fmt=='synthetic-tenable':parsed.update(tenant=first['tenant'],scan_id=first['scan_id'],exported_at=first['exported_at'],findings=findings)
        elif fmt=='synthetic-defender':parsed.update(tenantId=first['tenant'],scanId=first['scan_id'],exportedAt=first['exported_at'],value=findings)
        else:raise ValueError('Unsupported synthetic scanner format')
    elif name.lower().endswith('.json'):
        parsed=json.loads(text,object_pairs_hook=_unique_keys);fmt=parsed.get('format') if isinstance(parsed,dict) else None
    else:raise ValueError('Unsupported file type; use synthetic CSV or JSON')
    if fmt not in ('synthetic-tenable','synthetic-defender'):raise ValueError('Unsupported scanner envelope; production vendor exports need a separately validated adapter')
    if selected!='Auto detect' and selected!=fmt:raise ValueError('Selected scanner format does not match the file')
    return canonical(parsed).encode(),fmt

def preview(manager,generation,content,name,selected='Auto detect'):
    normalized,fmt=decode(content,name,selected)
    with manager.execution(generation,'preview_scanner_upload_rollback') as (path,w,clock,receipt):
        e=make_engine(path)
        try:
            with e.connect() as c:
                tx=c.begin()
                try:
                    result=ingest_export(c,w['id'],w['scenario_version_id'],normalized,fmt)
                    rows=[dict(r) for r in c.execute(select(tables['raw_findings']).where(tables['raw_findings'].c.workspace_id==w['id'],tables['raw_findings'].c.ingestion_batch_id==result['batch_id'])).mappings()]
                    return dict(format=fmt,upload_hash=digest([name,normalized.decode(),w['database_identity'],generation]),import_result=result,
                        rows=[dict(index=i+1,status=r['validation_status'],issues=json.loads(r['validation_errors_json']),record=json.loads(r['payload_json'])) for i,r in enumerate(rows)],
                        duplicates=len(rows)-len({r['payload_hash'] for r in rows}),
                        mapping=dict(asset='host_uuid' if fmt=='synthetic-tenable' else 'deviceId',component='component_key' if fmt=='synthetic-tenable' else 'softwareKey',
                            vulnerability='cve' if fmt=='synthetic-tenable' else 'cveId',severity='severity',timestamp='last_seen' if fmt=='synthetic-tenable' else 'detectedAt'))
                finally:tx.rollback() # no raw, normalized, evidence or operational changes
        finally:e.dispose()

def import_upload(manager,generation,*,content,name,selected,preview_hash,confirmed,actor,reason):
    if not confirmed or not actor.strip() or not reason.strip():raise ValueError('Named analyst and explicit import confirmation required')
    if redact(actor)!=actor or redact(reason)!=reason:raise ValueError('Secret-shaped analyst/rationale refused')
    normalized,fmt=decode(content,name,selected)
    with manager.execution(generation,'import_confirmed_scanner_upload') as (path,w,clock,receipt):
        if digest([name,normalized.decode(),w['database_identity'],generation])!=preview_hash:raise ValueError('Upload/workspace changed after preview; validate it again')
        e=make_engine(path)
        try:
            with e.begin() as c:
                result=ingest_export(c,w['id'],w['scenario_version_id'],normalized,fmt)
                from .services import audit
                audit(c,w['id'],'BrowserScannerImport','ingestion_batches',result['batch_id'],0,dict(actor=actor,reason=reason,original_filename=name,upload_hash=preview_hash,minimized_ai_context_only=True),actor_id=actor,actor_type='analyst')
                receipt.update(result);return result
        finally:e.dispose()

def sample(name,csv_format=False):
    from .fixture_builder import FIXTURE_DIR
    parsed=json.loads((FIXTURE_DIR/name).read_text(encoding='utf-8'))
    if not csv_format:return canonical(parsed).encode()
    fmt=parsed['format'];rows=parsed['findings'] if fmt=='synthetic-tenable' else parsed['value'];prepared=[]
    for row in rows:
        if not isinstance(row,dict):continue
        values=dict(row)
        if isinstance(values.get('cve'),list):values['cve']=';'.join(values['cve'])
        values.update(format=fmt,format_version='1',synthetic='true',tenant=parsed.get('tenant',parsed.get('tenantId')),
            scan_id=parsed.get('scan_id',parsed.get('scanId')),exported_at=parsed.get('exported_at',parsed.get('exportedAt')))
        prepared.append(values)
    out=io.StringIO();writer=csv.DictWriter(out,fieldnames=sorted({k for r in prepared for k in r}));writer.writeheader();writer.writerows(prepared);return out.getvalue().encode()
