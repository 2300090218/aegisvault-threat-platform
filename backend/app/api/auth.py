"""Authentication and user profile endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_app_settings, get_current_user, require_roles
from app.core.config import Settings
from app.core.database import get_db
from app.core.security import UserRole, create_access_token, verify_password
from app.models.db import User
from app.models.schemas import LoginRequest, TokenResponse, UserOut
from app.privacy.audit import append_audit_log

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> TokenResponse:
    user = db.execute(select(User).where(User.username == payload.username.strip())).scalar_one_or_none()
    if user is None or not user.is_active or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(
        subject=user.username,
        user_id=user.id,
        role=user.role,
        settings=settings,
    )
    append_audit_log(
        db,
        actor_id=user.id,
        actor_role=user.role,
        action="USER_LOGIN",
        resource_type="user",
        resource_id=user.id,
        details={"username": user.username},
    )
    db.commit()
    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(current_user)


@router.get("/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles(UserRole.PRIVACY_OFFICER, UserRole.ADMIN)),
) -> list[UserOut]:
    users = db.execute(select(User).order_by(User.created_at.asc())).scalars().all()
    return [UserOut.model_validate(u) for u in users]
