"""
bot.py — FSM MemoryStorage əlavəsi ilə yenilənmiş versiyadır.
DeepScan wizard-ı üçün Dispatcher-ə storage vermək məcburidir.
"""
import os
from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN tapılmadı")

bot = Bot(token=BOT_TOKEN)
dp  = Dispatcher(storage=MemoryStorage())   # ← FSM üçün storage əlavə edildi

from backend.app.bot.handlers import router

dp.include_router(router)
