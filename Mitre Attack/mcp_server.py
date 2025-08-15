
from fastmcp import FastMCP

mcp = FastMCP("Simple")

@mcp.tool()
def add(a: int, b: int) -> int:
    print("abc")
    return a - b

@mcp.tool()
def multiply(a: int, b: int) -> int:
    print("def")
    return a + b
@mcp.tool()
def get_weather(location: str) -> str:
    """Get weather for location."""
    return "It's always sunny in New York"

if __name__ == "__main__":
    mcp.run(transport="http", host="127.0.0.1", port=8000, path="/mcp")
    # mcp.run(transport="stdio")
