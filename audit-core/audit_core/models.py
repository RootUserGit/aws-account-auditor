import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class AwsAccountStatus(str, enum.Enum):
    pending = "pending"
    verified = "verified"
    error = "error"


class AuditRunStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    cancelled = "cancelled"


class FindingStatus(str, enum.Enum):
    passed = "passed"
    failed = "failed"
    unknown = "unknown"


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    aws_accounts: Mapped[list["AwsAccount"]] = relationship(back_populates="organization")


class AwsAccount(Base):
    __tablename__ = "aws_accounts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    account_id: Mapped[str] = mapped_column(String(12), nullable=False)
    #: Human-friendly label in the UI (e.g. "Prod payments").
    display_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    #: Free-form environment tag for filtering (e.g. prod, staging, UAT — not AWS data).
    environment: Mapped[str] = mapped_column(String(128), nullable=False, default="other")
    role_arn: Mapped[str] = mapped_column(String(512), nullable=False)
    external_id: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default=AwsAccountStatus.pending.value)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verify_error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    organization: Mapped["Organization"] = relationship(back_populates="aws_accounts")
    runs: Mapped[list["AuditRun"]] = relationship(back_populates="account")


class AuditRun(Base):
    __tablename__ = "audit_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    account_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("aws_accounts.id"), nullable=False)
    #: Set when the API enqueues the run (UI / POST). Used for history ordering; worker sets ``started_at``.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    status: Mapped[str] = mapped_column(String(32), default=AuditRunStatus.queued.value)
    rule_pack_version: Mapped[str] = mapped_column(String(64), default="v1")
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    summary_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: RQ job id for cancel while queued; cooperative cancel while running via cancel gates.
    rq_job_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    account: Mapped["AwsAccount"] = relationship(back_populates="runs")
    findings: Mapped[list["Finding"]] = relationship(back_populates="run")
    artifacts: Mapped[list["Artifact"]] = relationship(back_populates="run")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("audit_runs.id"), nullable=False)
    check_id: Mapped[str] = mapped_column(String(128), nullable=False)
    pillar: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    war_theme: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: CIS AWS Foundations Benchmark v1.5 control id when mapped (e.g. "5.2", "2.1.1").
    cis_control: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    evidence_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    remediation_hint: Mapped[str | None] = mapped_column(Text, nullable=True)

    run: Mapped["AuditRun"] = relationship(back_populates="findings")


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("audit_runs.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    storage_uri: Mapped[str] = mapped_column(String(2048), nullable=False)

    run: Mapped["AuditRun"] = relationship(back_populates="artifacts")
