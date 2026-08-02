"""Redacted models emitted by the real runtime measurement suite."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MeasurementSample(BaseModel):
    """One bounded real-runtime duration and its non-secret proof fields."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    detail_by_name_map: dict[str, Any] = Field(default_factory=dict)
    duration_seconds: float = Field(ge=0)
    name: str = Field(min_length=1)


class RuntimeMeasurementReport(BaseModel):
    """Complete redacted result for one exact image, platform, and snapshot run."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    architecture: str = Field(min_length=1)
    diagnostic: str = ""
    image_identity: str = Field(min_length=1)
    sample_list: list[MeasurementSample]
    status: str
    t_complete: datetime
    t_start: datetime
