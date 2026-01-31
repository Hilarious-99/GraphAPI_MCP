# Microsoft Graph MCP Server

MCP server for Microsoft Graph API services, designed for use with Claude Desktop and other MCP clients.

## Features

- **Defender Advanced Hunting** - Run KQL queries against Microsoft Defender
- **Entra ID Users** - Look up and search users in Azure AD

## Tools

| Tool | Description |
|------|-------------|
| `hunt(query, days)` | Run KQL queries against Defender Advanced Hunting |
| `get_user(user_id, select)` | Get user info by UPN or object ID |
| `list_users(filter, select, orderby, top, search, count)` | List/search users with OData queries |

## Setup

### 1. Azure AD App Registration

1. Go to [Azure Portal](https://portal.azure.com) > Azure Active Directory > App registrations
2. Create a new registration
3. Add API permissions:
   - `ThreatHunting.Read.All` (Defender Advanced Hunting)
   - `User.Read.All` (Entra ID users)
4. Grant admin consent
5. Create a client secret

### 2. Environment Variables

Create a `.env` file in the project root:

```
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
```

### 3. Install Dependencies

```bash
uv sync
```

### 4. Configure Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "microsoft-security": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/GraphAPI_MCP", "python", "defender_hunting.py"]
    }
  }
}
```

## Usage Examples

### Defender Hunting

```
Hunt for sign-in events:
AADSignInEventsBeta | where Timestamp > ago(7d) | limit 10

Hunt for process events:
DeviceProcessEvents | where Timestamp > ago(1d) | limit 10
```

### User Queries

```
Get user by UPN: get_user("user@domain.com")
List users in Sales: list_users(filter="department eq 'Sales'")
Search by name: list_users(search='"displayName:John"')
```

## Adding New Tools

Add new tools to `defender_hunting.py` using the `@mcp.tool()` decorator:

```python
@mcp.tool()
async def get_incidents(days: int = 7) -> str:
    """Get Microsoft Sentinel incidents."""
    result = await graph_request(
        method="GET",
        endpoint=f"/security/incidents?$filter=createdDateTime ge {date}",
    )
    return format_results(result)
```

## License

MIT
