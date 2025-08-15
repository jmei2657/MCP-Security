import os, json, asyncio, argparse, re
from openai import OpenAI
from pathlib import Path
from dotenv import load_dotenv
import requests

# Load .env from the same directory as this script
load_dotenv(dotenv_path=Path(__file__).with_name(".env"))
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
MCP_URL = "http://localhost:8001"  # adjust if your MCP server sits elsewhere

# 2. Tell OpenAI about your MCP tools (here as a single example;
#    you can expand this list to cover every endpoint your server offers)
functions = [
    {
        "type": "function",
        "name": "get_objects_by_content",
        "description": "Get MITRE ATT&CK objects by the content of their description",
        "parameters": {
            "type": "object",
            "properties": {
                "content": {
                    "type": "string",
                    "description": "Text to search for in object descriptions",
                },
                "object_type": {
                    "type": "string",
                    "description": "STIX object type (e.g. 'attack-pattern','malware',…)",
                },
                "domain": {
                    "type": "string",
                    "description": "Domain ('enterprise', 'mobile', or 'ics')",
                    "default": "enterprise",
                },
                "include_description": {
                    "type": "boolean",
                    "description": "Whether to return each object's description",
                    "default": False,
                },
            }
        },
    },
    {
        "type": "function",
        "name" : "get_all_techniques",
        "description" : "Get all techniques in the MITRE ATT&CK framework",
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain ('enterprise', 'mobile', or 'ics')",
                    "default": "enterprise",
                },
                "include_description": {
                    "type": "boolean",
                    "description": "Whether to return each object's description",
                    "default": False,
                }
            }
        }
    }
]

import itertools

MCP_BASE = "http://127.0.0.1:8001/mitre-mcp"
SESSION_ID = None
REQUEST_IDS = itertools.count(1)


def ensure_session():
    """Initialize a Streamable-HTTP MCP session once."""
    global SESSION_ID
    if SESSION_ID:
        return
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    init_body = {
        "jsonrpc": "2.0",
        "id": next(REQUEST_IDS),
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "simple-client", "version": "0.1.0"},
        },
    }
    resp = requests.post(MCP_BASE, json=init_body, headers=headers)
    resp.raise_for_status()
    # FastMCP returns the session id in this header (case-insensitive)
    SESSION_ID = resp.headers.get("mcp-session-id") or resp.headers.get(
        "Mcp-Session-Id"
    )

    # Optional but polite: tell the server we’re ready
    requests.post(
        MCP_BASE,
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers={**headers, "Mcp-Session-Id": SESSION_ID},
    )


def call_mcp(tool_name: str, args: dict) -> dict:
    ensure_session()
    body = {
        "jsonrpc": "2.0",
        "id": next(REQUEST_IDS),
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": args},
    }
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Mcp-Session-Id": SESSION_ID,
    }
    # stream=True lets us read SSE if the server chooses event-stream
    resp = requests.post(MCP_BASE, json=body, headers=headers, stream=True)
    resp.raise_for_status()

    ctype = resp.headers.get("Content-Type", "")
    if ctype.startswith("application/json"):
        data = resp.json()
        return data.get("result", data)

    if ctype.startswith("text/event-stream"):
        # Read SSE until we see a JSON-RPC message with the matching id
        for raw in resp.iter_lines(decode_unicode=True):
            if not raw:
                continue
            if raw.startswith("data:"):
                payload = raw[len("data:") :].strip()
                if not payload:
                    continue
                msg = json.loads(payload)
                # Per spec, server may send other messages first; match our id
                if msg.get("id") == body["id"] and ("result" in msg or "error" in msg):
                    return msg.get("result", msg)
        raise RuntimeError("No JSON-RPC result received on SSE stream.")

    # Fallback: show a helpful error
    raise RuntimeError(f"Unexpected Content-Type: {ctype} (status {resp.status_code})")


def ask_with_tools(prompt: str):
    # 1. Invoke GPT-4 with the function schema
    resp = client.responses.create(
        model="gpt-4o-mini",
        input=[{"role": "user", "content": prompt}],
        tools=functions,
    )
    # print(resp)
    tool_call = resp.output[0]
    args = json.loads(tool_call.arguments)
    # 2. If GPT decided to call your tool, proxy it with the right headers
    if tool_call is not None:
        name = tool_call.name
        args = json.loads(tool_call.arguments)

        try:
            result = call_mcp(name, args)
            print(f"\n🛠 Called {name} with:\n{json.dumps(args, indent=2)}")
            # print(f"→ Result:\n{json.dumps(result, indent=2)}")
        except requests.HTTPError as e:
            print("MCP server error:", e.response.text)
            return

    else:
        # 3. Otherwise, just print the LLM's reply
        print("\n💬", tool_call.content)


if __name__ == "__main__":
    vulnerability_description = """
    The remote SSH host key has been generated on a Debian or Ubuntu system which contains a bug in the random number generator of its OpenSSL library.
    The problem is due to a Debian packager removing nearly all sources of entropy in the remote version of OpenSSL. An attacker can easily obtain the private part of the remote key and use this to decipher the remote session or set up a man-in-the-middle attack.
    """

    user_prompt = f"""Here is the description of a vulnerability: {vulnerability_description}
    1. Identify any MITRE ATT&CK techniques, malware, or tools related to this vulnerability (include descriptions).
    2. Also retrieve a list of all techniques in the framework so we can compare them against known weaknesses."""

    ask_with_tools(user_prompt)
