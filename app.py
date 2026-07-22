from fastapi import FastAPI
from urllib.parse import urlparse
import os
import re
import shlex
import base64

app = FastAPI(title="TDS GA5 API")


# ============================================================
# Root
# ============================================================

@app.get("/")
def home():
    return {"status": "running"}


# ============================================================
# Question 2
# Endpoint: /policy
# ============================================================

@app.post("/policy")
def policy(data: dict):

    old_price = float(data["old_price"])
    new_price = float(data["new_price"])
    days_remaining = float(data["days_remaining"])
    days_in_actual_month = float(data["days_in_actual_month"])
    spec = data["spec"]

    diff = new_price - old_price

    if spec == "v1":
        charge = diff * (days_remaining / 30)

    elif spec == "v2":
        charge = diff * (days_remaining / days_in_actual_month)

    else:
        return {"error": "invalid spec"}

    return {"charge": round(charge, 2)}


# ============================================================
# Question 3
# Endpoint: /proration
# ============================================================

RESTRICTED = "/home/agent/.bashrc"
WRITE_ROOT = os.path.realpath("/data/agent/outbox")

ALLOWED_HOSTS = {
    "raw.githubusercontent.com",
    "huggingface.co",
}


def normalize(path):
    path = os.path.expandvars(path)
    path = os.path.expanduser(path)
    return os.path.realpath(os.path.normpath(path))


def restricted_path(path):
    return normalize(path) == normalize(RESTRICTED)


def contains_restricted(command: str):

    expanded = os.path.expandvars(command)
    expanded = expanded.replace("~", "/home/agent")

    if RESTRICTED in expanded:
        return True

    try:
        tokens = shlex.split(expanded)
    except Exception:
        tokens = expanded.split()

    for token in tokens:

        token = token.strip("\"'")

        if restricted_path(token):
            return True

        try:
            decoded = base64.b64decode(token + "==").decode(
                "utf-8",
                errors="ignore"
            )

            decoded = os.path.expandvars(decoded)
            decoded = decoded.replace("~", "/home/agent")

            if RESTRICTED in decoded:
                return True

        except Exception:
            pass

    relative_patterns = [
        "../.bashrc",
        "../../.bashrc",
        "../../../.bashrc",
    ]

    for p in relative_patterns:
        if p in expanded:
            return True

    return False


@app.post("/proration")
def guardrail(data: dict):

    tool = data.get("tool")

    # ------------------------------------------------

    if tool == "bash":

        command = data.get("command", "")

        if contains_restricted(command):
            return {
                "decision": "block",
                "reason": "Restricted file."
            }

        return {
            "decision": "allow",
            "reason": "Allowed."
        }

    # ------------------------------------------------

    elif tool == "write_file":

        path = normalize(data.get("path", ""))

        try:
            if os.path.commonpath([WRITE_ROOT, path]) != WRITE_ROOT:
                return {
                    "decision": "block",
                    "reason": "Write outside allowed directory."
                }
        except ValueError:
            return {
                "decision": "block",
                "reason": "Invalid path."
            }

        return {
            "decision": "allow",
            "reason": "Allowed."
        }

    # ------------------------------------------------

    elif tool == "http_request":

        url = data.get("url", "")

        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""

        if host not in ALLOWED_HOSTS:
            return {
                "decision": "block",
                "reason": "Host not allowed."
            }

        return {
            "decision": "allow",
            "reason": "Allowed."
        }

    return {
        "decision": "block",
        "reason": "Unknown tool."
    }


# ============================================================
# Question 4
# Endpoint: /scan
# ============================================================

SECRET_PATTERNS = [

    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z\-_]{35}",
    r"sk-[A-Za-z0-9]{20,}",
    r"ghp_[A-Za-z0-9]{20,}",
    r"gho_[A-Za-z0-9]{20,}",
    r"hf_[A-Za-z0-9]{20,}",
    r"xox[baprs]-[A-Za-z0-9\-]+",
    r"https://hooks\.slack\.com/",
    r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY-----",
]

PROMPT_PATTERNS = [

    "ignore previous instructions",
    "ignore the user",
    "ignore user",
    "ignore system prompt",
    "ignore safety",
    "ignore stop",
    "ignore cancel",
    "override user",
    "silently upload",
    "silently send",
    "without informing",
    "exfiltrate",
    "send local files",
]

PERMISSION_PATTERNS = [

    "filesystem: all",
    "filesystem: *",
    "filesystem: /",
    "read: /",
    "write: /",
    "network: all",
    "network: *",
    "allow_all",
    "all domains",
    "any domain",
    "internet: unrestricted",
]

PROVENANCE_REWRITE = [

    "rewrite version",
    "update version automatically",
    "modify frontmatter",
    "increment version",
    "change metadata",
]


@app.post("/scan")
def scan(data: dict):

    text = data.get("skill", "")
    lower = text.lower()

    categories = []

    # --------------------------------------------------------
    # hardcoded_secret
    # --------------------------------------------------------

    found = False

    for pattern in SECRET_PATTERNS:
        if re.search(pattern, text):
            found = True
            break

    if not found:

        for key in [
            "api_key",
            "apikey",
            "secret",
            "password",
            "token",
            "webhook",
        ]:

            m = re.search(
                rf"{key}\s*:\s*(.+)",
                lower
            )

            if m:

                value = m.group(1).strip()

                if (
                    "${" not in value
                    and "env(" not in value
                    and "<" not in value
                ):
                    found = True
                    break

    if found:
        categories.append("hardcoded_secret")

    # --------------------------------------------------------
    # prompt injection
    # --------------------------------------------------------

    if any(p in lower for p in PROMPT_PATTERNS):
        categories.append("prompt_injection")

    # --------------------------------------------------------
    # excessive permissions
    # --------------------------------------------------------

    if any(p in lower for p in PERMISSION_PATTERNS):
        categories.append("excessive_permissions")

    # --------------------------------------------------------
    # unclear provenance
    # --------------------------------------------------------

    author = "author:" in lower
    version = "version:" in lower
    changelog = "changelog:" in lower

    if not (author and version and changelog):
        categories.append("unclear_provenance")

    elif any(p in lower for p in PROVENANCE_REWRITE):
        categories.append("unclear_provenance")

    return {
        "categories": categories
    }
