from __future__ import annotations

import argparse
import os

from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from .config import Settings
from .models import Audit, Base, SchemaVersion, User
from .security import password_hash


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["init-db", "bootstrap-admin"])
    args = parser.parse_args()
    settings = Settings.from_env()
    engine = create_engine(settings.database_url)
    if args.command == "init-db":
        existing = set(inspect(engine).get_table_names())
        expected = set(Base.metadata.tables)
        if existing & expected and not expected <= existing:
            parser.error("partial schema exists; no automatic repair/migration")
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            versions = db.scalars(select(SchemaVersion.version)).all()
            if versions and versions != [1]:
                parser.error("unsupported schema version")
            if not versions:
                db.add(SchemaVersion(version=1))
                db.commit()
        print("platform v1 schema ready")
        return
    username = os.getenv("BOOTSTRAP_ADMIN_USERNAME", "").strip().lower()
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
    if not username or not 12 <= len(password) <= 256:
        parser.error("BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD (at least 12 chars) required")
    with Session(engine) as db:
        if db.get(SchemaVersion, 1) is None:
            parser.error("run init-db first")
        if db.scalar(select(User).where(User.username == username)):
            parser.error("admin username already exists")
        user = User(username=username, display_name=os.getenv("BOOTSTRAP_ADMIN_DISPLAY_NAME", username), role="admin", tenant_id=None, password_hash=password_hash(password))
        db.add(user)
        db.flush()
        db.add(Audit(actor_user_id=user.id, action="admin.bootstrap", target=str(user.id), detail="local CLI"))
        db.commit()
    print("admin bootstrapped")


if __name__ == "__main__":
    main()
