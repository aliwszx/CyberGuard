import logging
import asyncio

from aiogram import Router, types
from aiogram.filters import Command

from backend.scanners.whois_scanner import WhoisScanner
from backend.scanners.ip_scanner import IPScanner

logging.basicConfig(level=logging.INFO)

router = Router()

whois_scanner = WhoisScanner()
ip_scanner = IPScanner()


# =========================
# WHOIS
# =========================
@router.message(Command("whois"))
async def whois_cmd(message: types.Message):
    logging.info(f"WHOIS COMMAND RECEIVED: {message.text}")

    args = message.text.split()

    if len(args) < 2:
        await message.answer(
            "❌ İstifadə:\n<code>/whois google.com</code>",
            parse_mode="HTML"
        )
        return

    domain = args[1].strip().lower()

    wait_msg = await message.answer(
        f"🔍 <b>{domain}</b> üçün WHOIS məlumatları yoxlanılır...",
        parse_mode="HTML"
    )

    try:
        loop = asyncio.get_running_loop()

        result = await loop.run_in_executor(
            None,
            whois_scanner.scan,
            domain
        )

        logging.info(f"WHOIS RESULT: {result}")

        await wait_msg.delete()

        if result.get("status") == "error":
            await message.answer(
                f"❌ <b>Xəta:</b>\n<code>{result.get('error')}</code>",
                parse_mode="HTML"
            )
            return

        text = (
            "🌍 <b>WHOIS Məlumatı</b>\n"
            "────────────────────\n"
            f"🌐 Domain: <code>{result.get('domain')}</code>\n"
            f"🏢 Registrar: <code>{result.get('registrar') or 'N/A'}</code>\n"
            f"📅 Yaradılma: <code>{result.get('creation_date') or 'N/A'}</code>\n"
            f"⏳ Bitmə: <code>{result.get('expiration_date') or 'N/A'}</code>\n"
            f"🖧 Name Servers: <code>{result.get('name_servers') or 'N/A'}</code>"
        )

        await message.answer(text, parse_mode="HTML")

    except Exception as e:
        logging.exception("WHOIS ERROR")

        try:
            await wait_msg.delete()
        except:
            pass

        await message.answer(
            f"❌ WHOIS sorğusunda xəta:\n<code>{str(e)}</code>",
            parse_mode="HTML"
        )


# =========================
# IP Intelligence
# =========================
@router.message(Command("ipintel"))
async def ipintel_cmd(message: types.Message):
    logging.info(f"IPINTEL COMMAND RECEIVED: {message.text}")

    args = message.text.split()

    if len(args) < 2:
        await message.answer(
            "❌ İstifadə:\n"
            "<code>/ipintel google.com</code>\n"
            "və ya\n"
            "<code>/ipintel 8.8.8.8</code>",
            parse_mode="HTML"
        )
        return

    target = args[1].strip()

    wait_msg = await message.answer(
        f"🔍 <b>{target}</b> üçün IP məlumatları yoxlanılır...",
        parse_mode="HTML"
    )

    try:
        loop = asyncio.get_running_loop()

        result = await loop.run_in_executor(
            None,
            ip_scanner.scan,
            target
        )

        logging.info(f"IP RESULT: {result}")

        await wait_msg.delete()

        if result.get("status") == "error":
            await message.answer(
                f"❌ <b>Xəta:</b>\n<code>{result.get('error')}</code>",
                parse_mode="HTML"
            )
            return

        text = (
            "🌐 <b>IP Intelligence</b>\n"
            "────────────────────\n"
            f"📡 IP: <code>{result.get('ip')}</code>\n"
            f"🖥 Hostname: <code>{result.get('hostname')}</code>"
        )

        await message.answer(text, parse_mode="HTML")

    except Exception as e:
        logging.exception("IPINTEL ERROR")

        try:
            await wait_msg.delete()
        except:
            pass

        await message.answer(
            f"❌ IP analizində xəta:\n<code>{str(e)}</code>",
            parse_mode="HTML"
        )
