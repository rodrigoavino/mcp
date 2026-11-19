import asyncio, json, sys
from fastmcp import Client
from windows_rca_mcp.server import mcp

sys.stdout.reconfigure(encoding="utf-8")

def parse(v):
    try:
        return json.loads(v)
    except ValueError:
        return v

async def main():
    tool = sys.argv[1]
    args = {}
    for a in sys.argv[2:]:
        k, v = a.split("=", 1)
        args[k] = parse(v)
    async with Client(mcp) as c:
        r = await c.call_tool(tool, args)
        print(r.content[0].text if r.content else json.dumps(r.structured_content if r.structured_content is not None else [], ensure_ascii=False))

asyncio.run(main())
