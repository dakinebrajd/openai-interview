"""Offline deterministic M2 demonstration. No reset, model calls or external actions."""

import argparse
import json
from pathlib import Path

from .database import make_engine, migrate
from .fixture_builder import FIXTURE_DIR
from .register import build_register, export_register
from .scanners import ingest_export
from .scenario import load_scenario, seed_scenario


def run_demo(database, output_dir, fixture_dir=FIXTURE_DIR):
    manifest, files = load_scenario(fixture_dir)
    database = Path(database)
    database.parent.mkdir(parents=True, exist_ok=True)
    engine = make_engine(database)
    try:
        migrate(engine)
        with engine.begin() as c:
            workspace_id, version_id = seed_scenario(c, manifest, files)
            imports = []
            for name, format_name in [('tenable.json', 'synthetic-tenable'),
                                      ('defender.json', 'synthetic-defender'),
                                      ('tenable_repeat.json', 'synthetic-tenable')]:
                imports.append({'file': name, **ingest_export(c, workspace_id, version_id, files[name], format_name)})
            register = build_register(c, workspace_id)
            for key, expected in manifest['expected'].items():
                if register['summary'][key] != expected:
                    raise ValueError(f'Scenario acceptance mismatch for {key}: {register["summary"][key]} != {expected}')
        export_register(register, output_dir)
        return dict(label=register['label'], summary=register['summary'], imports=imports,
                    database=str(database), output_directory=str(output_dir))
    finally:
        engine.dispose()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=Path('artifacts/m2-demo.sqlite3'))
    parser.add_argument('--output-dir', type=Path, default=Path('artifacts/m2'))
    args = parser.parse_args()
    print(json.dumps(run_demo(args.database, args.output_dir), indent=2))


if __name__ == '__main__':
    main()
