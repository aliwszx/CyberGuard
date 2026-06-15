import asyncio

from fastapi import FastAPI

from backend.app.database.connection import engine
from backend.app.database.base import Base

from backend.app.bot.bot import bot, dp

app = FastAPI(title="CyberGuard")


@app.on_event("startup")
async def startup():

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    asyncio.create_task(dp.start_polling(bot))


@app.get("/")
async def root():
    return {"status": "CyberGuard running"}
