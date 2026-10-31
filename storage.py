
import os
from datetime import datetime, timezone

from sqlalchemy import (
    create_engine,
    String,
    Text,
    DateTime,
    UniqueConstraint,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    sessionmaker,
)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./mailroom.db")

# Use the psycopg 3 driver for PostgreSQL.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql+psycopg://",
        1,
    )
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgresql://",
        "postgresql+psycopg://",
        1,
    )

connect_args = (
    {"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite")
    else {}
)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(
    bind=engine,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


class Evaluation(Base):
    __tablename__ = "evaluations"

    evaluation_id: Mapped[str] = mapped_column(
        String(255), primary_key=True
    )
    input_digest: Mapped[str] = mapped_column(String(64))
    propose_request_digest: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    verifier_jwk: Mapped[str] = mapped_column(Text)
    propose_response: Mapped[str] = mapped_column(Text)
    commit_response: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    commit_request_digest: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
    )


class StoredReceipt(Base):
    __tablename__ = "stored_receipts"

    id: Mapped[int] = mapped_column(
        primary_key=True, autoincrement=True
    )
    evaluation_id: Mapped[str] = mapped_column(
        String(255), index=True
    )
    receipt_id: Mapped[str] = mapped_column(String(255))
    receipt_json: Mapped[str] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("evaluation_id", "receipt_id"),
    )


class DecisionCache(Base):
    __tablename__ = "decision_cache"

    fingerprint: Mapped[str] = mapped_column(
        String(64), primary_key=True
    )
    dossier_id: Mapped[str] = mapped_column(String(255))
    proposal_json: Mapped[str] = mapped_column(Text)


Base.metadata.create_all(engine)


def get_session():
    return SessionLocal()
