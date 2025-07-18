from typing import Literal, Optional
from pydantic import BaseModel

class FileReport(BaseModel):
    sha256: str
    verdict: Literal["Clean", "Malicious", "Unknown", "Pup"]
    detection: Optional[str]
    fileType: Optional[str]
    mimeType: Optional[str]
