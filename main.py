from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
import hashlib

EMAIL = "24f3005108@ds.study.iitm.ac.in".strip().lower()

mcp = FastMCP("exam-mcp")


@mcp.tool(name="solve_challenge")
async def solve_challenge(request: Request) -> str:
    """
    Reads X-Exam-Challenge from the HTTP headers and returns
    the first 16 lowercase hex characters of
    SHA256(challenge:normalizedEmail).
    """

    challenge = request.headers.get("X-Exam-Challenge", "")

    digest = hashlib.sha256(
        f"{challenge}:{EMAIL}".encode()
    ).hexdigest()

    return digest[:16]


app = mcp.streamable_http_app()
