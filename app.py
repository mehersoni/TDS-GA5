from fastapi import FastAPI
from urllib.parse import urlparse
import os
import re
import base64

app = FastAPI()

# =====================================================
# Question 2 - Proration Calculator
# Endpoint: /policy
# =====================================================

@app.post("/policy")
def calculate_proration(data: dict):
    old_price = data["old_price"]
    new_price = data["new_price"]
    days_remaining = data["days_remaining"]
    days_in_actual_month = data["days_in_actual_month"]
    spec = data["spec"]

    difference = new_price - old_price

    if spec == "v1":
        charge = difference * (days_remaining / 30)
    elif spec == "v2":
        charge = difference * (days_remaining / days_in_actual_month)
    else:
        return {"error": "Invalid specification"}

    return {"charge": round(charge, 2)}


# =====================================================
# Question 3 - Guardrail Hook
# Endpoint: /proration
# =====================================================

RESTRICTED = "/home/agent/.bashrc"
WRITE_ROOT = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "raw.githubusercontent.com",
    "huggingface.co"
}


def normalize(path):
    path = os.path.expandvars(path)
    path = os.path.expanduser(path)
    return os.path.realpath(os.path.normpath(path))


def contains_restricted(command):
    command = os.path.expandvars(command)
    command = command.replace("~", "/home/agent")

    if RESTRICTED in command:
        return True

    try:
        decoded = base64.b64decode(command).decode(errors="ignore")
        if RESTRICTED in decoded:
            return True
    except:
        pass

    return False


@app.post("/proration")
def guardrail(data: dict):

    tool = data.get("tool")

    # ----------------------------
    # bash
    # ----------------------------
    if tool == "bash":
        command = data.get("command", "")

        if contains_restricted(command):
            return {
                "decision": "block",
                "reason": "Restricted file access."
            }

        return {
            "decision": "allow",
            "reason": "Allowed."
        }

    # ----------------------------
    # write_file
    # ----------------------------
    elif tool == "write_file":
        path = normalize(data.get("path", ""))

        root = normalize(WRITE_ROOT)

        if not path.startswith(root):
            return {
                "decision": "block",
                "reason": "Write outside permitted directory."
            }

        return {
            "decision": "allow",
            "reason": "Allowed."
        }

    # ----------------------------
    # http_request
    # ----------------------------
    elif tool == "http_request":
        url = data.get("url", "")

        hostname = urlparse(url).hostname

        if hostname not in ALLOWED_HOSTS:
            return {
                "decision": "block",
                "reason": "Host not permitted."
            }

        return {
            "decision": "allow",
            "reason": "Allowed."
        }

    return {
        "decision": "block",
        "reason": "Unknown tool."
    }


# =====================================================
# Question 4 - Skill Scanner
# Endpoint: /scan
# =====================================================

SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z\-_]{35}",
    r"sk-[A-Za-z0-9]{20,}",
    r"https://hooks\.slack\.com/",
    r"ghp_[A-Za-z0-9]{20,}",
]

PERMISSION_PATTERNS = [
    "filesystem: all",
    "network: all",
    "write: /",
    "read: /",
    "permissions: all",
]

INJECTION_PATTERNS = [
    "ignore the user",
    "ignore previous instructions",
    "ignore stop request",
    "ignore cancel",
    "exfiltrate",
    "silently upload",
    "send all files",
]

PROVENANCE_FIELDS = [
    "author:",
    "version:",
    "changelog:"
]


@app.post("/scan")
def scan_skill(data: dict):

    text = data.get("skill", "")

    categories = []

    # ----------------------------
    # Hardcoded secret
    # ----------------------------
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, text):
            categories.append("hardcoded_secret")
            break

    # ----------------------------
    # Prompt injection
    # ----------------------------
    lower = text.lower()

    if any(x in lower for x in INJECTION_PATTERNS):
        categories.append("prompt_injection")

    # ----------------------------
    # Excessive permissions
    # ----------------------------
    if any(x in lower for x in PERMISSION_PATTERNS):
        categories.append("excessive_permissions")

    # ----------------------------
    # Provenance
    # ----------------------------
    if not all(field in lower for field in PROVENANCE_FIELDS):
        categories.append("unclear_provenance")

    return {
        "categories": categories
    }


# =====================================================
# Health Check
# =====================================================

@app.get("/")
def root():
    return {"status": "running"}
