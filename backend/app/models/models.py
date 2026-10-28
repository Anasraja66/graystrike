"""
Database Models — APT Agents
All tables with UUID primary keys and tenant isolation
"""
import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, Integer,
    Float, ForeignKey, Enum, JSON, UniqueConstraint, Index
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base


def utcnow():
    return datetime.now(timezone.utc)


def gen_uuid():
    return str(uuid.uuid4())


# =============================================
# ENUMS
# =============================================

class UserRole(str, PyEnum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class ScanStatus(str, PyEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingSeverity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, PyEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    READY_RETEST = "ready_retest"
    RESOLVED = "resolved"
    REGRESSION_DETECTED = "regression_detected"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class VerificationStatus(str, PyEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    NEEDS_REVIEW = "needs_review"
    NOT_REPRODUCED = "not_reproduced"
    FALSE_POSITIVE = "false_positive"


class SubscriptionPlan(str, PyEnum):
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


# =============================================
# USERS
# =============================================

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    is_superadmin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    org_memberships = relationship("OrganizationMember", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


# =============================================
# ORGANIZATIONS (Multi-tenant)
# =============================================

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    plan = Column(Enum(SubscriptionPlan), default=SubscriptionPlan.FREE)
    max_projects = Column(Integer, default=3)
    max_scans_per_month = Column(Integer, default=10)
    is_active = Column(Boolean, default=True)
    slack_webhook_url = Column(String(500), nullable=True)
    discord_webhook_url = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    members = relationship("OrganizationMember", back_populates="organization")
    projects = relationship("Project", back_populates="organization")
    subscriptions = relationship("Subscription", back_populates="organization")
    audit_logs = relationship("AuditLog", back_populates="organization")


class OrganizationMember(Base):
    __tablename__ = "organization_members"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    organization_id = Column(UUID(as_uuid=False), ForeignKey("organizations.id"), nullable=False)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.VIEWER)
    joined_at = Column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)

    organization = relationship("Organization", back_populates="members")
    user = relationship("User", back_populates="org_memberships")


# =============================================
# API KEYS (Machine-to-Machine CI/CD Credentials)
# =============================================

class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    organization_id = Column(UUID(as_uuid=False), ForeignKey("organizations.id"), nullable=False, index=True)
    project_id = Column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=True, index=True)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=False)
    name = Column(String(100), default="CI/CD GitHub Action Key")
    key_prefix = Column(String(20), nullable=False)
    key_hash = Column(String(64), nullable=False, index=True)
    scopes = Column(JSON, default=lambda: ["scans:create", "scans:read", "findings:read"])
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    organization = relationship("Organization")
    project = relationship("Project")
    user = relationship("User")


# =============================================
# PROJECTS (Websites to test)
# =============================================

class Project(Base):
    __tablename__ = "projects"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    organization_id = Column(UUID(as_uuid=False), ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    base_url = Column(String(500), nullable=False)
    is_active = Column(Boolean, default=True)
    scan_schedule = Column(String(50), default="manual")
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)
    next_scan_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    organization = relationship("Organization", back_populates="projects")
    domains = relationship("Domain", back_populates="project")
    scans = relationship("Scan", back_populates="project")
    scope_policies = relationship("ScopePolicy", back_populates="project")


# =============================================
# DOMAINS (Ownership verification)
# =============================================

class Domain(Base):
    __tablename__ = "domains"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    project_id = Column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    hostname = Column(String(255), nullable=False)
    verification_token = Column(String(255), unique=True)
    is_verified = Column(Boolean, default=False)
    verified_at = Column(DateTime(timezone=True))
    verification_expires_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    project = relationship("Project", back_populates="domains")
    verifications = relationship("DomainVerification", back_populates="domain")


class DomainVerification(Base):
    __tablename__ = "domain_verifications"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    domain_id = Column(UUID(as_uuid=False), ForeignKey("domains.id"), nullable=False)
    checked_at = Column(DateTime(timezone=True), default=utcnow)
    success = Column(Boolean, default=False)
    dns_response = Column(JSON)
    error_message = Column(Text)

    domain = relationship("Domain", back_populates="verifications")


# =============================================
# SCOPE POLICY (Safety enforcement)
# =============================================

class ScopePolicy(Base):
    __tablename__ = "scope_policies"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    project_id = Column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)
    allowed_hosts = Column(JSON, default=list)       # ["example.com", "api.example.com"]
    denied_paths = Column(JSON, default=list)        # ["/admin", "/api/internal"]
    allowed_methods = Column(JSON, default=list)     # ["GET", "POST"]
    max_requests = Column(Integer, default=1000)
    max_depth = Column(Integer, default=5)
    rate_limit_rps = Column(Float, default=2.0)      # Requests per second
    authenticated_testing = Column(Boolean, default=False)
    active_checks_enabled = Column(Boolean, default=False)  # OFF by default!
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    project = relationship("Project", back_populates="scope_policies")


# =============================================
# SCANS
# =============================================

class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    project_id = Column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=False), ForeignKey("organizations.id"), nullable=False, index=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.QUEUED)
    current_stage = Column(String(100))
    target_url = Column(String(500))

    # Metrics
    pages_discovered = Column(Integer, default=0)
    endpoints_found = Column(Integer, default=0)
    agents_run = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    # AI Usage
    total_tokens = Column(Integer, default=0)
    estimated_cost_usd = Column(Float, default=0.0)

    # Timing
    queued_at = Column(DateTime(timezone=True), default=utcnow)
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    duration_seconds = Column(Integer)

    # CI/CD Context & Idempotency
    commit_sha = Column(String(40), index=True, nullable=True)
    pull_request_number = Column(Integer, nullable=True)
    ci_provider = Column(String(50), nullable=True)

    error_message = Column(Text)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")
    events = relationship("ScanEvent", back_populates="scan")
    reports = relationship("Report", back_populates="scan")


class ScanEvent(Base):
    """Real-time scan events streamed to frontend via WebSocket."""
    __tablename__ = "scan_events"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id"), nullable=False, index=True)
    event_type = Column(String(100))  # stage_started, finding_found, agent_complete
    message = Column(Text)
    data = Column(JSON)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    scan = relationship("Scan", back_populates="events")


# =============================================
# FINDINGS (Vulnerabilities)
# =============================================

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id"), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=False), ForeignKey("organizations.id"), nullable=False, index=True)
    project_id = Column(UUID(as_uuid=False), ForeignKey("projects.id"), nullable=False)

    # Classification
    title = Column(String(500), nullable=False)
    category = Column(String(100))          # e.g., "sql_injection"
    cwe_id = Column(String(20))             # e.g., "CWE-89"
    owasp_ref = Column(String(20))          # e.g., "A03:2021"
    affected_asset = Column(String(500))    # URL/endpoint affected

    # Evidence
    evidence_summary = Column(Text)
    http_request = Column(Text)
    http_response = Column(Text)
    screenshot_url = Column(String(500))

    # Severity & Confidence
    severity = Column(Enum(FindingSeverity), nullable=False)
    confidence = Column(Float, default=0.0)     # 0.0 - 1.0
    risk_score = Column(Float, default=0.0)     # RIRAG formula
    cvss_vector = Column(String(200))
    cvss_score = Column(Float)

    # Verification
    verification_status = Column(Enum(VerificationStatus), default=VerificationStatus.NEEDS_REVIEW)
    verification_method = Column(String(100))

    # Remediation
    business_impact = Column(Text)
    technical_explanation = Column(Text)
    remediation_steps = Column(Text)
    ai_fix_prompt = Column(Text)
    references = Column(JSON, default=list)

    # Workflow & Deduplication
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN)
    fingerprint = Column(String(64), index=True)
    first_seen_at = Column(DateTime(timezone=True), default=utcnow)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow)
    retest_status = Column(String(50), default="untested")
    retest_notes = Column(Text)
    last_retested_at = Column(DateTime(timezone=True))
    discovered_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    scan = relationship("Scan", back_populates="findings")
    evidence = relationship("FindingEvidence", back_populates="finding")
    comments = relationship("FindingComment", back_populates="finding")


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id"), nullable=False)
    evidence_type = Column(String(50))  # screenshot, http_request, console_log
    content = Column(Text)
    file_url = Column(String(500))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    finding = relationship("Finding", back_populates="evidence")


class FindingComment(Base):
    __tablename__ = "finding_comments"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id"), nullable=False)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    finding = relationship("Finding", back_populates="comments")


# =============================================
# REPORTS
# =============================================

class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    scan_id = Column(UUID(as_uuid=False), ForeignKey("scans.id"), nullable=False)
    organization_id = Column(UUID(as_uuid=False), ForeignKey("organizations.id"), nullable=False)
    title = Column(String(500))
    pdf_url = Column(String(500))
    json_url = Column(String(500))
    generated_at = Column(DateTime(timezone=True), default=utcnow)

    scan = relationship("Scan", back_populates="reports")


# =============================================
# AUDIT LOGS
# =============================================

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    organization_id = Column(UUID(as_uuid=False), ForeignKey("organizations.id"), nullable=True, index=True)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)     # e.g., "scan.created"
    resource_type = Column(String(100))              # e.g., "scan"
    resource_id = Column(String(255))
    log_metadata = Column(JSON)
    ip_address = Column(String(45))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    organization = relationship("Organization", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("idx_audit_logs_org_created", "organization_id", "created_at"),
    )


# =============================================
# SUBSCRIPTIONS
# =============================================

class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    organization_id = Column(UUID(as_uuid=False), ForeignKey("organizations.id"), nullable=False)
    plan = Column(Enum(SubscriptionPlan), default=SubscriptionPlan.FREE)
    stripe_subscription_id = Column(String(255))
    is_active = Column(Boolean, default=True)
    current_period_start = Column(DateTime(timezone=True))
    current_period_end = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)

    organization = relationship("Organization", back_populates="subscriptions")
