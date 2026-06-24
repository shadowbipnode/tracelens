from typing import Any, Dict, List, Literal

from pydantic import BaseModel


class CollectorResult(BaseModel):
    source: str
    status: Literal["ok", "error", "skipped"]
    data: Dict[str, Any]
    errors: List[str]
    started_at: str
    completed_at: str
