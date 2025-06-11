from pydantic import BaseModel

class ProblemDetails(BaseModel):
    type: str
    detail: str

