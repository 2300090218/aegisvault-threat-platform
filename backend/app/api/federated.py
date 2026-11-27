"""Federated Learning (FedAvg) status, training rounds, and reset endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.core.database import get_db
from app.core.security import UserRole
from app.detection.federated import FederatedSimulator
from app.models.db import User
from app.models.schemas import FederatedStatusOut, FederatedTrainRequest
from app.privacy.audit import append_audit_log

router = APIRouter(prefix="/federated", tags=["federated"])
_simulator = FederatedSimulator()


@router.get("/status", response_model=FederatedStatusOut)
def get_federated_status(
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
) -> FederatedStatusOut:
    return _simulator.get_status(db)


@router.post("/train-round", response_model=FederatedStatusOut)
def run_federated_rounds(
    payload: FederatedTrainRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(UserRole.ANALYST, UserRole.PRIVACY_OFFICER, UserRole.ADMIN)
    ),
) -> FederatedStatusOut:
    status_out = _simulator.run_rounds(
        db,
        rounds=payload.rounds,
        local_epochs=payload.local_epochs,
    )
    append_audit_log(
        db,
        actor_id=current_user.id,
        actor_role=current_user.role,
        action="FEDERATED_ROUND_EXECUTED",
        resource_type="federated_model",
        resource_id=f"round_{status_out.current_round}",
        details={
            "rounds_run": payload.rounds,
            "current_round": status_out.current_round,
            "global_accuracy": status_out.global_accuracy,
        },
    )
    db.commit()
    return status_out


@router.post("/reset", response_model=FederatedStatusOut)
def reset_federated_demo(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN, UserRole.PRIVACY_OFFICER)),
) -> FederatedStatusOut:
    out = _simulator.reset(db)
    append_audit_log(
        db,
        actor_id=current_user.id,
        actor_role=current_user.role,
        action="FEDERATED_DEMO_RESET",
        resource_type="federated_model",
        resource_id="reset",
        details={},
    )
    db.commit()
    return out
