from typing import Literal, Optional
from pydantic import BaseModel

class VaasVerdict(BaseModel):
    sha256: str
    verdict: Literal["Clean", "Malicious", "Unknown", "Pup"]
    detection: Optional[str]
    fileType: Optional[str]
    mimeType: Optional[str]

    @staticmethod
    def from_report(report):
        return VaasVerdict(
            sha256=report.sha256,
            verdict=report.verdict,
            detection=report.detection,
            fileType=report.fileType,
            mimeType=report.mimeType
        )
