from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class LogEvent(BaseModel):
    timestamp: str
    source_ip: str
    service: str
    event_type: str
    payload: str


class LoginRequest(BaseModel):
    username: str = Field(..., examples=["admin"])
    password: str = Field(..., examples=["admin123"])


class DeviceTokenRequest(BaseModel):
    fcm_token: str = Field(..., min_length=10)


class MobileIncidentRequest(BaseModel):
    source_ip: Optional[str] = Field(
        default=None,
        examples=["192.168.1.50"],
        description="Opcjonalny adres IP / źródło incydentu (puste = automatyczne IP z VPN)",
    )
    asset_id: str = Field(
        ..., examples=["SRV-LAB-04"], description="ID zeskanowane z kodu QR"
    )
    description: str = Field(
        ..., examples=["Niezablokowany terminal z otwartą sesją root"]
    )
    severity: str = Field(default="HIGH", examples=["HIGH"])
    latitude: Optional[float] = Field(default=None, examples=[54.1943])
    longitude: Optional[float] = Field(default=None, examples=[16.1722])
    client_created_at: Optional[str] = Field(
        default=None,
        examples=["2026-11-27T08:00:00Z"],
        description="Czas UTC z telefonu (kolejka offline)",
    )


class AlertStatusEnum(str, Enum):
    NEW = "NEW"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"


class AlertStatusUpdateRequest(BaseModel):
    status: AlertStatusEnum
    client_updated_at: str = Field(
        ...,
        examples=["2026-11-27T08:05:00Z"],
        description="Czas UTC modyfikacji na telefonie do strategii Last-Write-Wins",
    )


class HealthTarget(str, Enum):
    all = "all"
    collector_1 = "collector-1"
    collector_2 = "collector-2"
    collector_3 = "collector-3"
    random = "random"
