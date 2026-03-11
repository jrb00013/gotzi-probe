"""PostgreSQL connection and session factory."""

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from udp_probe.core.config import get_config
from udp_probe.models.base import Base

_engine = None
_SessionFactory: sessionmaker[Session] | None = None


def get_engine():
    global _engine
    if _engine is None:
        cfg = get_config()
        _engine = create_engine(
            cfg.database_url,
            pool_pre_ping=True,
            echo=False,
        )
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine(), autocommit=False, autoflush=False, expire_on_commit=False)
    return _SessionFactory


def get_session() -> Session:
    return get_session_factory()()


def init_db() -> None:
    """Create all tables."""
    Base.metadata.create_all(bind=get_engine())
