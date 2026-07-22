from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.responses import JSONResponse

app = FastAPI()


class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: float
    days_in_actual_month: float
    spec: str


@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/")
async def calculate(request: ProrationRequest):
    difference = request.new_price - request.old_price

    if request.spec == "v1":
        charge = difference * (request.days_remaining / 30.0)

    elif request.spec == "v2":
        charge = difference * (
            request.days_remaining / request.days_in_actual_month
        )

    else:
        return JSONResponse(
            status_code=400,
            content={"error": "Invalid spec"},
        )

    return {"charge": float(charge)}
