import asyncio
import sys
import os

_backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

from fastapi import FastAPI
from backend.app.database.connection import engine
from backend.app.database.base import Base

# bot.py import ediləndə router-lər artıq qeydiyyatdan keçmiş olur
from backend.app.bot.bot import bot, dp
from backend.services.scanner_service import ScannerService

app = FastAPI(title="CyberGuard")
scanner = ScannerService()


@app.on_event("startup")
async def startup():
    # Router-lər bot.py-da artıq qeydiyyatdan keçib, burada əlavə etmirik
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    asyncio.create_task(dp.start_polling(bot))


@app.get("/")
def root():
    return {"status": "CyberGuard running"}


@app.get("/scan/{domain}")
def scan_domain(domain: str):
    return scanner.full_scan(domain)
