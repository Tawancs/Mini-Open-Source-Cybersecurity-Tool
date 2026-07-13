from pydantic import BaseModel
from typing import Dict, Any, Optional

class RequestModel(BaseModel):
    method: str
    url: str
    params: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
