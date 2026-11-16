from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field

ClassificationStatus = Literal[
    "CLASSIFIED",
    "UNKNOWN",
    "INSUFFICIENT_EVIDENCE",
    "UNSUPPORTED",
]

CategoryAssessmentStatus = Literal[
    "CONFIRMED",
    "SUSPECTED",
    "ABSENT",
    "UNSUPPORTED",
]

# Standard Taxonomy Definition
MALWARE_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "loader": {
        "id": "loader",
        "name": "Loader",
        "type": "behavior",
        "description": "Loads secondary payloads or stages into memory for execution.",
    },
    "stealer": {
        "id": "stealer",
        "name": "Stealer",
        "type": "behavior",
        "description": "Harvests credentials, browser cookies, crypto wallets, or confidential system data.",
    },
    "botnet": {
        "id": "botnet",
        "name": "Botnet",
        "type": "behavior",
        "description": "Connects to command-and-control infrastructure to receive remote group commands (e.g. DDoS, scanning).",
    },
    "backdoor": {
        "id": "backdoor",
        "name": "Backdoor",
        "type": "behavior",
        "description": "Establishes unauthorized persistent remote access to execute commands or manipulate files.",
    },
    "rootkit": {
        "id": "rootkit",
        "name": "Rootkit",
        "type": "behavior",
        "description": "Operates at kernel or deep OS level to hide malware existence, processes, or registry keys.",
    },
    "launcher": {
        "id": "launcher",
        "name": "Launcher",
        "type": "behavior",
        "description": "Spawns or bootstraps execution of secondary processes with specific operational flags.",
    },
    "injector": {
        "id": "injector",
        "name": "Injector",
        "type": "behavior",
        "description": "Manipulates memory of remote processes to inject and execute foreign shellcode or DLLs.",
    },
    "dropper": {
        "id": "dropper",
        "name": "Dropper",
        "type": "behavior",
        "description": "Extracts and drops embedded binary payloads to disk and initiates their execution.",
    },
    "downloader": {
        "id": "downloader",
        "name": "Downloader",
        "type": "behavior",
        "description": "Fetches secondary binary payloads or scripts from remote URLs and saves them locally.",
    },
    "ransomware": {
        "id": "ransomware",
        "name": "Ransomware",
        "type": "behavior",
        "description": "Inhibits system recovery, encrypts user files, or creates extortion notes demanding ransom.",
    },
    "kernel_driver": {
        "id": "kernel_driver",
        "name": "Kernel Driver",
        "type": "component",
        "description": "Installs or operates a Windows kernel-mode driver (.sys). Note: drivers may be benign or malicious.",
    },
    "phishing": {
        "id": "phishing",
        "name": "Phishing",
        "type": "delivery",
        "description": "Social engineering or credential harvesting page/delivery lure. (Unsupported on Windows PE).",
    },
    "rat": {
        "id": "rat",
        "name": "RAT",
        "type": "behavior",
        "description": "Remote Access Trojan with interactive management, surveillance, shell, or screen capture.",
    },
    "spyware": {
        "id": "spyware",
        "name": "Spyware",
        "type": "behavior",
        "description": "Monitors keystrokes, clipboard, screen, or user activity without consent.",
    },
    "obfuscation": {
        "id": "obfuscation",
        "name": "Obfuscation",
        "type": "characteristic",
        "description": "Packed, encrypted, or anti-analysis code characteristics. (Code characteristic, not standalone malware verdict).",
    },
    "wiper": {
        "id": "wiper",
        "name": "Wiper",
        "type": "behavior",
        "description": "Deliberately destroys or wipes disk sectors, system partitions, or user files without recovery mechanism.",
    },
    "android_rat": {
        "id": "android_rat",
        "name": "Android RAT",
        "type": "behavior",
        "description": "Remote Access Trojan targeting Android platform (.apk). (Unsupported on Windows PE).",
    },
}

UNSUPPORTED_PE_CATEGORIES = ["phishing", "android_rat"]


class CategoryAssessment(BaseModel):
    category_id: str
    category_name: str
    category_type: str = "behavior"  # behavior, component, characteristic, delivery
    classification_status: CategoryAssessmentStatus
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_ids: List[str] = Field(default_factory=list)
    supporting_static_function_ids: List[str] = Field(default_factory=list)
    supporting_dynamic_event_ids: List[int] = Field(default_factory=list)
    supporting_artifact_ids: List[str] = Field(default_factory=list)
    explanation: str
    contradictory_evidence: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class MalwareClassificationResult(BaseModel):
    analysis_id: str
    sample_sha256: str
    taxonomy_version: str = "1.0"
    classifier_version: str = "1.0.0"
    primary_category: Optional[str] = None
    secondary_categories: List[str] = Field(default_factory=list)
    suspected_family: Optional[str] = None
    family_confidence: Optional[float] = None
    overall_evidence_quality: str = "VERIFIED"
    classification_status: ClassificationStatus = "UNKNOWN"
    classification_findings: List[CategoryAssessment] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    unsupported_categories: List[str] = Field(default_factory=lambda: list(UNSUPPORTED_PE_CATEGORIES))
