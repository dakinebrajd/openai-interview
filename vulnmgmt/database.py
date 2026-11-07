"""SQLite connections and transactional, checksum-verified migration runner."""

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import URL

from .migrations import v0001, v0002, v0003


def make_engine(path: str | Path):
    """Explicit path only: no implicit local database is created on import."""
    engine = create_engine(URL.create('sqlite', database=str(path)), connect_args={'timeout': 5})

    @event.listens_for(engine, 'connect')
    def configure(dbapi_connection, _):
        dbapi_connection.isolation_level = None
        dbapi_connection.execute('PRAGMA foreign_keys=ON')
        dbapi_connection.execute('PRAGMA busy_timeout=5000')

    @event.listens_for(engine, 'begin')
    def begin(connection):
        # Explicit BEGIN avoids sqlite3 legacy autocommit of DDL and serializes writers.
        connection.exec_driver_sql('BEGIN IMMEDIATE')

    return engine


def migrate(engine):
    """Apply missing versions atomically; reject checksum changes and schema drift."""
    migrations = [(1, v0001), (2, v0002), (3, v0003)]
    checksums = {version: sha256(Path(module.__file__).read_text(encoding='utf-8').encode('utf-8')).hexdigest()
                 for version, module in migrations}
    with engine.begin() as connection:
        connection.exec_driver_sql('''CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY, checksum TEXT NOT NULL, schema_hash TEXT NOT NULL,
            applied_at TEXT NOT NULL)''')
        rows = connection.exec_driver_sql('SELECT version, checksum, schema_hash FROM schema_migrations ORDER BY version').all()
        if rows:
            if ([r[0] for r in rows] != list(range(1, len(rows)+1))
                    or any(version not in checksums or checksum != checksums[version] for version, checksum, _ in rows)):
                raise RuntimeError('Unknown migration version or changed migration checksum')
            expected = set(v0001.metadata.tables) | {'schema_migrations'}
            if len(rows) >= 2:
                expected |= set(v0002.NAMES)
            if len(rows) >= 3:
                expected |= set(v0003.NAMES)
            actual = set(connection.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").scalars())
            if actual != expected or connection.exec_driver_sql('PRAGMA foreign_key_check').first():
                raise RuntimeError('Schema is incomplete or foreign-key integrity is broken')
            if rows[-1][2] != schema_hash(connection):
                raise RuntimeError('Schema definition drift detected')
        existing = connection.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table' AND name != 'schema_migrations' "
            "AND name NOT LIKE 'sqlite_%'").all()
        if existing and not rows:
            raise RuntimeError('Refusing migration of an unversioned nonempty database')
        for version, module in migrations[len(rows):]:
            module.apply(connection)
            connection.exec_driver_sql('INSERT INTO schema_migrations VALUES (?, ?, ?, ?)',
                                      (version, checksums[version], schema_hash(connection),
                                       datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')))


def schema_hash(connection):
    definitions = connection.exec_driver_sql(
        "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL "
        "AND name NOT LIKE 'sqlite_%' ORDER BY type, name").all()
    return sha256(repr(definitions).encode('utf-8')).hexdigest()


tables = (dict(v0001.metadata.tables) | {name: v0002.metadata.tables[name] for name in v0002.NAMES}
          | {name: v0003.metadata.tables[name] for name in v0003.NAMES})
