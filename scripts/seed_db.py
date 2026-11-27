"""Standalone database bootstrap & seed CLI script."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.core.bootstrap import bootstrap_database  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.database import Base, init_db_globals, session_scope  # noqa: E402


def main() -> None:
    settings = get_settings()
    engine, sf = init_db_globals(settings)
    Base.metadata.create_all(engine)
    with session_scope(sf) as db:
        bootstrap_database(db, settings)
    print("Database bootstrapped and seeded successfully.")


if __name__ == "__main__":
    main()
