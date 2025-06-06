from typing import Optional
from pydantic import BaseModel

class UrlAnalysisRequest(BaseModel):
    url: str
    use_hash_lookup: Optional[bool] = True