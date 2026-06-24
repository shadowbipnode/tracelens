from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class CollectorResult(BaseModel):
    source: str
    status: Literal["ok", "error", "skipped"]
    data: Dict[str, Any]
    errors: List[str]
    error: Optional[Dict[str, Any]] = None
    error_details: List[Dict[str, Any]] = Field(default_factory=list)
    started_at: str
    completed_at: str
