from typing import Optional, Literal
from pydantic import BaseModel

class UrlReport(BaseModel):
    sha256: str
    verdict: Literal["Clean", "Malicious", "Unknown", "Pup"]
    url: str
    detection: Optional[str]
    fileType: Optional[str]
    mimeType: Optional[str]