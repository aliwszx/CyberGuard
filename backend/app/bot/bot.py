import os
from aiogram import Bot, Dispatcher
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN tapılmadı")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# Bütün handlerlər yalnız burada yüklənir
from backend.app.bot.handlers import router

dp.include_router(router)
