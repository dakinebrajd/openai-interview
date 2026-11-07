"""Read-only historical dashboard projection; no manager or migration initialization."""
from pathlib import Path
import sqlite3
from sqlalchemy import create_engine, select
from sqlalchemy.pool import NullPool
from .database import tables
from .dashboard_queries import dashboard


class HistoricalDashboard:
    read_only = True

    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)

    def _connect(self, path):
        path = Path(path).resolve(strict=True)
        if path.parent != self.root or path.suffix != '.sqlite3':
            raise ValueError('Historical database must stay inside the preserved directory')
        c = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA query_only=ON')
        return c

    def view(self, **filters):
        control = self._connect(self.root/'control.sqlite3')
        try:
            state = dict(control.execute('SELECT * FROM registry WHERE id=1').fetchone())
            path = self.root/state['active']
            engine = create_engine('sqlite://', creator=lambda: self._connect(path), poolclass=NullPool)
            try:
                with engine.connect() as c:
                    workspace = c.execute(select(tables['demo_workspaces'])).mappings().one()
                    result = dashboard(c, workspace['id'], state['clock'], **filters)
                    result['manager'] = state
                    return result
            finally:
                engine.dispose()
        finally:
            control.close()

    def execution(self, *args, **kwargs):
        raise ValueError('Historical dashboard is read only')

    reset = snapshot = execution
