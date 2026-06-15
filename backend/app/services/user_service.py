from sqlalchemy import select
from backend.app.database.connection import SessionLocal
from backend.app.models.user import User


class UserService:

    async def get_by_telegram_id(self, telegram_id: str):
        async with SessionLocal() as session:
            result = await session.execute(
                select(User).where(User.telegram_id == telegram_id)
            )
            return result.scalar_one_or_none()

    async def create_user(self, telegram_id: str, username: str | None):
        async with SessionLocal() as session:
            user = User(
                telegram_id=telegram_id,
                username=username
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            return user

    async def get_or_create_user(self, telegram_id: str, username: str | None):
        user = await self.get_by_telegram_id(telegram_id)
        if not user:
            user = await self.create_user(telegram_id, username)
        return user
