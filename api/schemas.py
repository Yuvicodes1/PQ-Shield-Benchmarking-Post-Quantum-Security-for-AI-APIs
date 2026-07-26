from pydantic import BaseModel, Field


class PredictRequest(BaseModel):
    input: list[float] = Field(..., min_length=64, max_length=64)


class PredictResponse(BaseModel):
    prediction: int
    probabilities: list[float]
    inference_ms: float
