import sys
import os
import time
import asyncio

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from app.main import app
import uvicorn

print("Imported app successfully!")

async def main():
    config = uvicorn.Config(app, host="127.0.0.1", port=8005, log_level="info")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    print("Server started on port 8005, waiting 25 seconds...")
    for i in range(25):
        await asyncio.sleep(1)
        if server.should_exit:
            print(f"Server signaled should_exit at {i}s!")
            break
    print("Done waiting.")
    server.should_exit = True
    await task

if __name__ == "__main__":
    asyncio.run(main())
