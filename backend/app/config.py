import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    DATABASE_URL = os.getenv("DATABASE_URL")
    BOT_TOKEN = os.getenv("BOT_TOKEN")
    SECRET_KEY = os.getenv("SECRET_KEY")

settings = Settings()