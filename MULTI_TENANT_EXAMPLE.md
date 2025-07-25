# Multi-Tenant MCP Atlassian Example

This guide demonstrates how to use the modified mcp-atlassian server in multi-tenant mode, where different users can connect with their own Atlassian instances without requiring separate deployments.

## Starting the Server

Start the server in minimal OAuth mode without specifying any URLs:

```bash
docker run --rm -p 9000:9000 \
  -e ATLASSIAN_OAUTH_ENABLE=true \
  ghcr.io/sooperset/mcp-atlassian:latest \
  --transport streamable-http --port 9000
```

Note: No JIRA_URL or CONFLUENCE_URL environment variables are required!

## Client Configuration

### Example 1: Different Companies on Different Atlassian Instances

```json
{
  "mcpServers": {
    "company-a-atlassian": {
      "url": "http://localhost:9000/mcp",
      "headers": {
        "Authorization": "Bearer <COMPANY_A_USER_OAUTH_TOKEN>",
        "X-Atlassian-Cloud-Id": "<COMPANY_A_CLOUD_ID>",
        "X-Jira-URL": "https://company-a.atlassian.net",
        "X-Confluence-URL": "https://company-a.atlassian.net/wiki"
      }
    },
    "company-b-atlassian": {
      "url": "http://localhost:9000/mcp",
      "headers": {
        "Authorization": "Bearer <COMPANY_B_USER_OAUTH_TOKEN>",
        "X-Atlassian-Cloud-Id": "<COMPANY_B_CLOUD_ID>",
        "X-Jira-URL": "https://company-b.atlassian.net",
        "X-Confluence-URL": "https://company-b.atlassian.net/wiki"
      }
    }
  }
}
```

### Example 2: Different Users on Same Instance

```json
{
  "mcpServers": {
    "atlassian-alice": {
      "url": "http://localhost:9000/mcp",
      "headers": {
        "Authorization": "Bearer <ALICE_OAUTH_TOKEN>",
        "X-Jira-URL": "https://mycompany.atlassian.net",
        "X-Confluence-URL": "https://mycompany.atlassian.net/wiki"
      }
    },
    "atlassian-bob": {
      "url": "http://localhost:9000/mcp",
      "headers": {
        "Authorization": "Bearer <BOB_OAUTH_TOKEN>",
        "X-Jira-URL": "https://mycompany.atlassian.net",
        "X-Confluence-URL": "https://mycompany.atlassian.net/wiki"
      }
    }
  }
}
```

### Example 3: Server/Data Center with PAT

```json
{
  "mcpServers": {
    "internal-jira": {
      "url": "http://localhost:9000/mcp",
      "headers": {
        "Authorization": "Token <USER_PERSONAL_ACCESS_TOKEN>",
        "X-Jira-URL": "https://jira.internal.company.com",
        "X-Confluence-URL": "https://confluence.internal.company.com"
      }
    }
  }
}
```

## Python Client Example

```python
import asyncio
from mcp.client.streamable_http import streamablehttp_client
from mcp import ClientSession

async def connect_to_company_a():
    # Company A's Atlassian instance
    async with streamablehttp_client(
        "http://localhost:9000/mcp",
        headers={
            "Authorization": "Bearer <COMPANY_A_OAUTH_TOKEN>",
            "X-Atlassian-Cloud-Id": "<COMPANY_A_CLOUD_ID>",
            "X-Jira-URL": "https://company-a.atlassian.net",
            "X-Confluence-URL": "https://company-a.atlassian.net/wiki"
        }
    ) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            
            # Get issue from Company A's Jira
            result = await session.call_tool(
                "jira_get_issue",
                {"issue_key": "PROJ-123"}
            )
            print(f"Company A Issue: {result}")

async def connect_to_company_b():
    # Company B's Atlassian instance
    async with streamablehttp_client(
        "http://localhost:9000/mcp",
        headers={
            "Authorization": "Bearer <COMPANY_B_OAUTH_TOKEN>",
            "X-Atlassian-Cloud-Id": "<COMPANY_B_CLOUD_ID>",
            "X-Jira-URL": "https://company-b.atlassian.net",
            "X-Confluence-URL": "https://company-b.atlassian.net/wiki"
        }
    ) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            
            # Search in Company B's Confluence
            result = await session.call_tool(
                "confluence_search",
                {"cql": "text ~ 'quarterly report'"}
            )
            print(f"Company B Results: {result}")

# Run both connections in parallel
async def main():
    await asyncio.gather(
        connect_to_company_a(),
        connect_to_company_b()
    )

asyncio.run(main())
```

## Key Benefits

1. **Single Deployment**: One server instance handles multiple Atlassian organizations
2. **Dynamic Configuration**: URLs and authentication are provided per-request
3. **Complete Isolation**: Each request uses its own credentials and accesses only its authorized data
4. **Flexible Authentication**: Supports both OAuth 2.0 (Cloud) and PAT (Server/DC)
5. **No Restarts Required**: Add new users/organizations without touching the server

## Required Headers

### For Atlassian Cloud (OAuth 2.0):
- `Authorization: Bearer <oauth_access_token>` (Required)
- `X-Atlassian-Cloud-Id: <cloud_id>` (Optional - helps with cloud instance identification)
- `X-Jira-URL: <jira_url>` (Required if using Jira)
- `X-Confluence-URL: <confluence_url>` (Required if using Confluence)

### For Server/Data Center (PAT):
- `Authorization: Token <personal_access_token>` (Required)
- `X-Jira-URL: <jira_url>` (Required if using Jira)
- `X-Confluence-URL: <confluence_url>` (Required if using Confluence)

## Security Notes

- Each request is authenticated individually
- No credentials are shared between requests
- URLs must be HTTPS for production use
- Consider using a reverse proxy for additional security layers 