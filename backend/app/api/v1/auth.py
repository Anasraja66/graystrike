"""
Authentication API — Register, Login, Refresh, Logout
"""
from fastapi import APIRouter, Depends, HTTPException, Header, Query, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional

from app.core.database import get_db
from app.core.security import hash_password, verify_password, create_access_token, create_refresh_token, decode_token
from app.models.models import User, Organization, OrganizationMember, UserRole, ApiKey
from app.schemas.auth import (
    UserRegister, UserLogin, TokenResponse, UserResponse, OrganizationCreate
)

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    token_query: Optional[str] = Query(None, alias="token"),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Unified Authenticator:
    Supports both Human JWT Bearer tokens (via header or query parameter) and Machine-to-Machine API Keys.
    """
    effective_token = token or token_query
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # 1. Check for API Key (CI/CD GitHub Actions)
    raw_api_key = x_api_key or (effective_token if effective_token and effective_token.startswith("apt_live_") else None)
    if raw_api_key:
        key_hash = hashlib.sha256(raw_api_key.strip().encode()).hexdigest()
        result = await db.execute(
            select(ApiKey, User)
            .join(User, ApiKey.user_id == User.id)
            .where(ApiKey.key_hash == key_hash, ApiKey.is_active == True)
        )
        row = result.first()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked API Key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        api_key_obj, user_obj = row
        now = datetime.now(timezone.utc)
        if api_key_obj.expires_at:
            exp = api_key_obj.expires_at if api_key_obj.expires_at.tzinfo else api_key_obj.expires_at.replace(tzinfo=timezone.utc)
            if exp < now:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API Key has expired")

        api_key_obj.last_used_at = now
        await db.commit()

        # Attach api_key metadata to user object
        user_obj._api_key = api_key_obj
        return user_obj

    # 2. Check for Standard JWT Bearer Token (Dashboard Web UI)
    if not effective_token:
        raise credentials_exception

    payload = decode_token(effective_token)
    if not payload or payload.get("type") != "access":
        raise credentials_exception

    user_id = payload.get("sub")
    if not user_id:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user:
        raise credentials_exception
    return user


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(data: UserRegister, db: AsyncSession = Depends(get_db)):
    """Register a new user and create their organization."""
    # Check if email exists
    result = await db.execute(select(User).where(User.email == data.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create user
    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
        full_name=data.full_name,
        is_verified=True,  # Skip email verification for now (dev mode)
    )
    db.add(user)
    await db.flush()  # Get user.id

    # Create organization
    slug = data.org_name.lower().replace(" ", "-") + "-" + secrets.token_hex(3)
    org = Organization(name=data.org_name, slug=slug)
    db.add(org)
    await db.flush()

    # Add user as owner
    membership = OrganizationMember(
        organization_id=org.id,
        user_id=user.id,
        role=UserRole.OWNER
    )
    db.add(membership)
    await db.commit()

    # Generate tokens
    access_token = create_access_token({"sub": user.id, "org_id": org.id})
    refresh_token = create_refresh_token({"sub": user.id})

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            org_id=org.id,
            org_name=org.name,
            role=UserRole.OWNER
        )
    )


@router.post("/login", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    """Login with email and password."""
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Account deactivated")

    # Get user's primary organization
    result = await db.execute(
        select(OrganizationMember, Organization)
        .join(Organization)
        .where(OrganizationMember.user_id == user.id)
        .order_by(OrganizationMember.joined_at)
        .limit(1)
    )
    row = result.first()
    org_id = row.OrganizationMember.organization_id if row else None
    org_name = row.Organization.name if row else None
    role = row.OrganizationMember.role if row else None

    access_token = create_access_token({"sub": user.id, "org_id": str(org_id) if org_id else None})
    refresh_token = create_refresh_token({"sub": user.id})

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            org_id=org_id,
            org_name=org_name,
            role=role
        )
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Get current user profile."""
    result = await db.execute(
        select(OrganizationMember, Organization)
        .join(Organization)
        .where(OrganizationMember.user_id == current_user.id)
        .limit(1)
    )
    row = result.first()
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        org_id=row.OrganizationMember.organization_id if row else None,
        org_name=row.Organization.name if row else None,
        role=row.OrganizationMember.role if row else None
    )
