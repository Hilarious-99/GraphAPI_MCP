"""
Microsoft Graph Authentication.

Reusable authentication module for all Microsoft services:
- Defender Advanced Hunting
- Microsoft Sentinel
- Intune
- Entra ID
- SharePoint
- etc.
"""

import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

# Load .env from project directory
load_dotenv(Path(__file__).parent / ".env")

TENANT_ID = os.environ.get("AZURE_TENANT_ID")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET")


def is_configured() -> bool:
    """Check if Azure credentials are configured."""
    return all([TENANT_ID, CLIENT_ID, CLIENT_SECRET])


async def get_graph_token() -> str:
    """
    Get Microsoft Graph access token.

    Uses client credentials flow (app-only authentication).
    Token is cached for reuse within the session.
    """
    if not is_configured():
        raise ValueError(
            "Missing Azure credentials. Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET."
        )

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
        )
        response.raise_for_status()
        return response.json()["access_token"]


async def graph_request(
    method: str,
    endpoint: str,
    json: dict | None = None,
    headers: dict | None = None,
    timeout: float = 120.0,
) -> dict:
    """
    Make an authenticated request to Microsoft Graph API.

    Args:
        method: HTTP method (GET, POST, etc.)
        endpoint: API endpoint (e.g., "/security/runHuntingQuery")
        json: Request body for POST/PATCH requests
        headers: Additional headers to include in the request
        timeout: Request timeout in seconds

    Returns:
        JSON response from the API
    """
    token = await get_graph_token()
    url = f"https://graph.microsoft.com/v1.0{endpoint}"

    request_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if headers:
        request_headers.update(headers)

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.request(
            method=method,
            url=url,
            headers=request_headers,
            json=json,
        )
        response.raise_for_status()
        return response.json()
