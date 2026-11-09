"""Allow running the MCP server as: python -m mobsf.MCP"""
import asyncio
from mobsf.MCP.server import main

asyncio.run(main())
