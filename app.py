from fastapi import FastAPI
from pydantic import BaseModel
import os
from urllib.parse import urlparse

app = FastAPI()

# -----------------------------
# Question 2: Proration
# -----------------------------

class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: float
    days_in_actual_month: float
    spec: str

@app.post("/proration")
def proration(req: ProrationRequest):
    diff = req.new_price - req.old_price

    if req.spec == "v1":
        charge = diff * (req.days_remaining / 30.0)
    elif req.spec == "v2":
        charge = diff * (req.days_remaining / req.days_in_actual_month)
    else:
        return {"error": "Invalid spec"}

    return {"charge": charge}


# -----------------------------
# Question 3: Policy Checker
# -----------------------------

class PolicyRequest(BaseModel):
    call: dict
    cfg: dict

def resolves_inside(path, root):
    full = (
        os.path.normpath(os.path.join(root, path))
        if not os.path.isabs(path)
        else os.path.normpath(path)
    )
    root = os.path.normpath(root)
    return full == root or full.startswith(root + os.sep)

def extract_host(url):
    return urlparse(url).hostname

@app.post("/policy")
def policy(req: PolicyRequest):
    call = req.call
    cfg = req.cfg

    tool = call["tool"]
    args = call["arguments"]

    if tool == "read_file":
        p = os.path.normpath(args["path"])
        if any(p.endswith(s) or s in p for s in cfg["secret_files"]):
            return {"decision": "block"}
        return {"decision": "allow"}

    if tool == "write_file":
        return {
            "decision": "allow"
            if resolves_inside(args["path"], cfg["write_dir"])
            else "block"
        }

    if tool in ("network", "fetch", "http"):
        host = extract_host(args["url"])
        return {
            "decision": "allow"
            if host in cfg["allowed_domains"]
            else "block"
        }

    return {"decision": "allow"}
