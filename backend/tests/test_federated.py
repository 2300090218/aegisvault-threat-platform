"""Unit tests for 3-organization Federated Learning (FedAvg) simulator."""

from __future__ import annotations

from app.detection.federated import FederatedSimulator


def test_federated_learning_improves_across_rounds_and_persists(db_session) -> None:
    sim = FederatedSimulator()
    initial = sim.get_status(db_session)
    assert initial.current_round == 0
    assert initial.rounds == []

    status = sim.run_rounds(db_session, rounds=4, local_epochs=3)
    db_session.commit()

    assert status.current_round == 4
    assert len(status.rounds) == 4
    for r in status.rounds:
        assert len(r.org_metrics) == 3
        org_ids = {m.org_id for m in r.org_metrics}
        assert org_ids == {"org_alpha", "org_beta", "org_gamma"}
        assert 0.0 <= r.global_accuracy <= 1.0

    # FedAvg converges well above random guessing on the shared global evaluation set
    assert status.global_accuracy >= 0.85
    assert status.rounds[-1].global_loss <= status.rounds[0].global_loss

    # Reset clears round history cleanly
    after_reset = sim.reset(db_session)
    db_session.commit()
    assert after_reset.current_round == 0
    assert after_reset.rounds == []
