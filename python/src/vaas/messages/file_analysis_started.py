from pydantic import BaseModel

class FileAnalysisStarted(BaseModel):
    sha256: str

