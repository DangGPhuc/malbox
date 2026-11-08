from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class BehavioralRule:
    rule_id: str
    title: str
    description: str
    severity: str  # Informational, Low, Medium, High, Critical
    confidence: float
    mitre_attack_id: Optional[str]
    mitre_tactic: Optional[str]
    score_weight: int

BEHAVIORAL_RULES: List[BehavioralRule] = [
    BehavioralRule(
        rule_id="RULE_SHADOW_COPY_DELETION",
        title="Volume Shadow Copy Deletion (Anti-Recovery)",
        description="Observed execution of commands designed to destroy volume shadow copies and prevent system recovery.",
        severity="Critical",
        confidence=0.98,
        mitre_attack_id="T1490",
        mitre_tactic="Impact",
        score_weight=40,
    ),
    BehavioralRule(
        rule_id="RULE_MASS_FILE_ENCRYPTION",
        title="High-Entropy File Encryption & Ransom Note Creation",
        description="Observed mass modification of user documents with encrypted extensions alongside the generation of a ransom note.",
        severity="Critical",
        confidence=0.95,
        mitre_attack_id="T1486",
        mitre_tactic="Impact",
        score_weight=45,
    ),
    BehavioralRule(
        rule_id="RULE_REGISTRY_RUN_PERSISTENCE",
        title="Persistence via Registry Run Key",
        description="Configured an autostart execution point in the Windows Registry (CurrentVersion\\Run) to survive reboots.",
        severity="High",
        confidence=0.90,
        mitre_attack_id="T1547.001",
        mitre_tactic="Persistence",
        score_weight=25,
    ),
    BehavioralRule(
        rule_id="RULE_POWERSHELL_OBFUSCATED",
        title="Encoded / Obfuscated PowerShell Command Execution",
        description="Spawned PowerShell with execution policy bypass flags and Base64-encoded command payload.",
        severity="High",
        confidence=0.92,
        mitre_attack_id="T1059.001",
        mitre_tactic="Execution",
        score_weight=25,
    ),
    BehavioralRule(
        rule_id="RULE_CREDENTIAL_VAULT_ACCESS",
        title="Web Browser Credential Store Access",
        description="Attempted to access and extract saved user credentials from Google Chrome or Mozilla Firefox profile stores.",
        severity="High",
        confidence=0.94,
        mitre_attack_id="T1555.003",
        mitre_tactic="Credential Access",
        score_weight=30,
    ),
    BehavioralRule(
        rule_id="RULE_C2_HTTP_EXFILTRATION",
        title="Suspicious HTTP Command & Control Exfiltration",
        description="Outbound HTTP POST request transmitted data to an external gate endpoint.",
        severity="High",
        confidence=0.88,
        mitre_attack_id="T1071.001",
        mitre_tactic="Command and Control",
        score_weight=25,
    ),
    BehavioralRule(
        rule_id="RULE_LATERAL_SMB_PROBE",
        title="SMB Network Service Discovery & Scanning",
        description="Initiated outbound connection attempts across port 445 indicative of lateral movement or SMB worm propagation.",
        severity="Medium",
        confidence=0.85,
        mitre_attack_id="T1046",
        mitre_tactic="Discovery",
        score_weight=15,
    ),
]
