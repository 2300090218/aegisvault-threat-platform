"""MITRE ATT&CK technique definitions used by rules and ML alerts."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    technique_name: str
    tactic: str


MITRE_TECHNIQUES: dict[str, MitreTechnique] = {
    "T1110": MitreTechnique(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
    ),
    "T1078": MitreTechnique(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Defense Evasion",
    ),
    "T1041": MitreTechnique(
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
    ),
    "T1046": MitreTechnique(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="Discovery",
    ),
    "T1204.002": MitreTechnique(
        technique_id="T1204.002",
        technique_name="User Execution: Malicious File",
        tactic="Execution",
    ),
    "T1071": MitreTechnique(
        technique_id="T1071",
        technique_name="Application Layer Protocol",
        tactic="Command and Control",
    ),
}
