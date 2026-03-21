from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, IPvAnyAddress


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class LogEvent(BaseModel):
    timestamp: datetime
    event: str
    user: str
    src_ip: IPvAnyAddress = Field(..., alias="ip")
    dst_ip: Optional[IPvAnyAddress] = None
    event_id: Optional[str] = None
    status: Optional[str] = None
    user_agent: Optional[str] = None
    raw: Dict[str, Any] = {}


class Alert(BaseModel):
    id: str
    rule: str
    type: str
    severity: SeverityLevel
    user: Optional[str]
    src_ip: Optional[IPvAnyAddress]
    dst_ip: Optional[IPvAnyAddress] = None
    message: str
    timestamp: Optional[datetime] = None
    context: Dict[str, Any] = {}
    mitre: Optional[List[str]] = None


class Incident(BaseModel):
    incident_id: str
    input_file: str
    generated_at: datetime
    alerts: List[Alert]
    timeline: List[Dict[str, Any]]
    observables: List[Dict[str, Any]]
    recommendations: List[str]
