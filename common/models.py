# common/models.py
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

@dataclass
class ThreatEvent:
    zone_id: str
    sensor_type: str          # "network", "file", "process"
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    file_path: Optional[str] = None          # for file sensor
    process_name: Optional[str] = None       # for process sensor
    threat_score: float = 0.0
    raw_data: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None

    def to_dict(self):
        return {k: v for k, v in asdict(self).items() if v is not None}

@dataclass
class ZonalReport:
    zone_id: str
    threat_score: float
    local_verdict: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

@dataclass
class AnalysisResult:
    threat_id: str
    zone_report: ThreatEvent
    similar_past_events: list
    llm_prompt: str
    llm_response: str
    verdict: str
    explanation: str
    timestamp: str