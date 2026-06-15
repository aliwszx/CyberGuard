import os
import sys
import asyncio
from aiogram import Bot, Dispatcher
from dotenv import load_dotenv

load_dotenv()

# Backend root-u sys.path-ə əlavə et
_backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN tapılmadı! .env faylını yoxla.")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# Router-ləri BİRBAŞA burada qeydiyyatdan keçir — heç bir lazy import yox
from app.bot.handlers import router
from app.bot.portscan_handler import router as portscan_router
from app.bot.osint_handler import router as osint_router

dp.include_router(router)
dp.include_router(portscan_router)
dp.include_router(osint_router)


async def main():
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
