"""Offline M3 enrichment against the M2 synthetic dataset. Live execution is disabled."""
import argparse
import json
from pathlib import Path
from sqlalchemy import select

from .database import make_engine, tables
from .demo import run_demo
from .enrichment import enrich
from .reasoning import run_live


def run_enrichment_demo(database=Path('artifacts/m2-demo.sqlite3'), output_dir=Path('artifacts/m3'),
                        *, use_assumptions=True, as_of=None, mode='replay'):
    if mode != 'replay':
        run_live()
    run_demo(database, Path(output_dir)/'m2-baseline')
    engine = make_engine(database)
    try:
        with engine.begin() as c:
            workspace = c.execute(select(tables['demo_workspaces'])).mappings().one()
        result = enrich(engine, workspace['id'], workspace['scenario_version_id'],
                        use_assumptions=use_assumptions, as_of=as_of)
    finally:
        engine.dispose()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir/'enrichment.json').write_text(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True)+'\n', encoding='utf-8')
    lines = ['# M3 source-backed replay', '',
             'Human-curated replay; zero model calls and zero current source retrievals. No batches approved.', '',
             f'Evidence reference time: {result["evidence_as_of"]}. Historical replay, not current research.', '',
             '## Summary', ''] + [f'- {k}: {v}' for k, v in result['summary'].items()]
    lines += ['', '## CVE dossiers', '']
    for dossier in result['cves']:
        g, t = dossier['remediation'], dossier['threat']
        lines += [f'### {g["cve_id"]}', '',
            f'Guidance: {g["status"]}; historical fixed release: {g["fixed_version"] or "Unresolved"}.', '',
            f'KEV: {t["kev_member"]}; EPSS: {t["epss_score"]} (score date {t["epss_date"]}); sector: {t["sector_targeting"]}.', '',
            'EPSS is a probability estimate, not evidence of exploitation. No state-government targeting inferred.', '']
        lines += [f'- {gap}' for gap in g['gaps']+t['gaps']]
        lines += ['', *[f'- [{name}]({url}); retrieved {result["sources"][name]["retrieved_at"]}; '
                        f'{result["sources"][name]["freshness"]}' for name, url in dossier['source_urls'].items()], '']
    lines += ['## Proposed batches — analyst review required', '']
    for batch in result['proposed_batches']:
        lines += [f'- {batch["asset_key"]}: {", ".join(batch["cve_ids"])}; {batch["action"]["instruction"]}',
                  f'  {batch["assumption"]["label"]}: {batch["assumption"]["product"]} {batch["assumption"]["installed_version"]}.',
                  '  Historical CVE-specific action only; review current vendor support before any real remediation.']
    lines += ['', '## Review gaps', '', *[f'- {gap}' for gap in result['evidence_gaps']]]
    (output_dir/'enrichment.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=Path('artifacts/m2-demo.sqlite3'))
    parser.add_argument('--output-dir', type=Path, default=Path('artifacts/m3'))
    parser.add_argument('--mode', choices=('replay', 'live'), default='replay')
    parser.add_argument('--no-assumptions', action='store_true')
    parser.add_argument('--as-of', default=None)
    args = parser.parse_args()
    result = run_enrichment_demo(args.database, args.output_dir, mode=args.mode,
                                use_assumptions=not args.no_assumptions, as_of=args.as_of)
    print(json.dumps({'mode': result['mode'], 'origin': result['origin'], 'summary': result['summary'],
                      'evidence_as_of': result['evidence_as_of'], 'reports': str(args.output_dir)}, indent=2))


if __name__ == '__main__':
    main()
