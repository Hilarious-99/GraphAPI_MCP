"""
MCP Server for Microsoft Defender Advanced Hunting.
"""

import httpx
from mcp.server.fastmcp import FastMCP

from auth import is_configured, graph_request

mcp = FastMCP("microsoft-security")


@mcp.tool()
async def hunt(query: str, days: int = 30) -> str:
    """
    Run a KQL query against Microsoft Defender Advanced Hunting.

    Args:
        query: KQL query to execute (e.g., "DeviceProcessEvents | limit 10")
        days: Number of days to look back (default: 30, max: 30)

    Returns:
        Query results as formatted text
    """
    if not is_configured():
        return "Error: Missing Azure credentials. Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET."

    try:
        result = await graph_request(
            method="POST",
            endpoint="/security/runHuntingQuery",
            json={
                "Query": query,
                "Timespan": f"P{min(days, 30)}D",
            },
        )

        rows = result.get("results", [])
        if not rows:
            return "No results found."

        output = [f"Found {len(rows)} results:\n"]
        for row in rows[:100]:
            output.append(str(row))

        if len(rows) > 100:
            output.append(f"\n... and {len(rows) - 100} more rows")

        return "\n".join(output)

    except httpx.HTTPStatusError as e:
        return f"API Error {e.response.status_code}: {e.response.text}"
    except Exception as e:
        return f"Error: {str(e)}"


# Default user properties to retrieve
DEFAULT_USER_SELECT = [
    "id",
    "displayName",
    "userPrincipalName",
    "mail",
    "jobTitle",
    "department",
    "officeLocation",
    "mobilePhone",
    "businessPhones",
    "accountEnabled",
    "createdDateTime",
    "lastSignInDateTime",
]


@mcp.tool()
async def get_user(user_id: str, select: list[str] | None = None) -> str:
    """
    Get user information from Microsoft Entra ID (Azure AD).

    Args:
        user_id: User identifier - can be UPN (user@domain.com) or object ID (GUID)
        select: List of properties to retrieve. If not provided, returns default properties.
                Examples: ["displayName", "mail"] or ["id", "signInActivity"]

    Returns:
        User profile information for the requested properties.
    """
    if not is_configured():
        return "Error: Missing Azure credentials. Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET."

    try:
        properties = select if select else DEFAULT_USER_SELECT
        select_param = ",".join(properties)

        result = await graph_request(
            method="GET",
            endpoint=f"/users/{user_id}?$select={select_param}",
        )

        # Format output
        lines = ["User Profile:", "-" * 40]
        for key, value in result.items():
            if value is not None and key != "@odata.context":
                lines.append(f"{key}: {value}")

        return "\n".join(lines)

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return f"User not found: {user_id}"
        return f"API Error {e.response.status_code}: {e.response.text}"
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def list_users(
    filter: str | None = None,
    select: list[str] | None = None,
    orderby: str | None = None,
    top: int | None = None,
    search: str | None = None,
    count: bool = False,
) -> str:
    """
    List and search users in Microsoft Entra ID with OData query support.

    Args:
        filter: OData filter expression. Examples:
            - "startswith(displayName, 'John')"
            - "department eq 'Sales'"
            - "accountEnabled eq true"
            - "userType eq 'Member'"
            - "createdDateTime ge 2024-01-01T00:00:00Z"
        select: List of properties to return. Default: displayName, userPrincipalName, id, mail
        orderby: Property to sort by. Examples: "displayName", "createdDateTime desc"
        top: Maximum number of users to return (max 999, default 100)
        search: Search expression (requires quotes). Examples:
            - '"displayName:John"'
            - '"mail:john@"'
        count: If True, include total count of matching users

    Returns:
        List of users matching the query criteria.
    """
    if not is_configured():
        return "Error: Missing Azure credentials. Set AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET."

    try:
        # Build query parameters
        params = []

        if select:
            params.append(f"$select={','.join(select)}")
        else:
            params.append("$select=id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled")

        if filter:
            params.append(f"$filter={filter}")

        if orderby:
            params.append(f"$orderby={orderby}")

        if top:
            params.append(f"$top={min(top, 999)}")
        else:
            params.append("$top=100")

        if search:
            params.append(f"$search={search}")

        if count:
            params.append("$count=true")

        query_string = "&".join(params)
        endpoint = f"/users?{query_string}"

        # Headers for advanced queries (required for $search and $count)
        headers = {}
        if search or count:
            headers["ConsistencyLevel"] = "eventual"

        result = await graph_request(
            method="GET",
            endpoint=endpoint,
            headers=headers,
        )

        users = result.get("value", [])
        total_count = result.get("@odata.count")

        if not users:
            return "No users found matching the criteria."

        # Format output
        lines = []
        if total_count is not None:
            lines.append(f"Total count: {total_count}")
        lines.append(f"Returned: {len(users)} users\n")
        lines.append("-" * 60)

        for user in users:
            user_info = []
            for key, value in user.items():
                if value is not None and not key.startswith("@"):
                    user_info.append(f"  {key}: {value}")
            lines.append("\n".join(user_info))
            lines.append("-" * 60)

        return "\n".join(lines)

    except httpx.HTTPStatusError as e:
        return f"API Error {e.response.status_code}: {e.response.text}"
    except Exception as e:
        return f"Error: {str(e)}"


if __name__ == "__main__":
    mcp.run()
