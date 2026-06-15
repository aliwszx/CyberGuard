import logging
logging.basicConfig(level=logging.DEBUG)

from aiogram import Router, types
from aiogram.filters import Command
import asyncio

# sys.path bot.py-da artıq set olunub
from backend.scanners.whois_scanner import WhoisScanner
from backend.scanners.ip_scanner import IPScanner

router = Router()

whois_scanner = WhoisScanner()
ip_scanner = IPScanner()


@router.message(Command("whois"))
async def whois_cmd(message: types.Message):
    print("WHOIS COMMAND RECEIVED:", message.text)
    
@router.message(Command("whois"))
async def whois_cmd(message: types.Message):
    args = message.text.split()

    if len(args) < 2:
        await message.answer(
            "❌ İstifadə: <code>/whois domain.com</code>",
            parse_mode="HTML"
        )
        return

    domain = args[1].strip()
    wait_msg = await message.answer(
        f"🔍 <b>{domain}</b> üçün WHOIS sorğusu...",
        parse_mode="HTML"
    )

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, whois_scanner.scan, domain)

    await wait_msg.delete()

    if result["status"] == "error":
        await message.answer(
            f"❌ <b>Xəta:</b> <code>{result['error']}</code>",
            parse_mode="HTML"
        )
        return

    text = (
        f"🌍 <b>WHOIS Məlumatı</b>\n"
        f"{'─' * 28}\n"
        f"🌐 Domain: <code>{result['domain']}</code>\n"
        f"🏢 Registrar: <code>{result.get('registrar') or 'N/A'}</code>\n"
        f"📅 Yaradılma: <code>{result.get('creation_date', 'N/A')}</code>\n"
        f"⏳ Bitmə tarixi: <code>{result.get('expiration_date', 'N/A')}</code>"
    )

    await message.answer(text, parse_mode="HTML")


@router.message(Command("ipintel"))
async def ip_cmd(message: types.Message):
    args = message.text.split()

    if len(args) < 2:
        await message.answer(
            "❌ İstifadə: <code>/ipintel domain.com</code> və ya <code>/ipintel 1.2.3.4</code>",
            parse_mode="HTML"
        )
        return

    target = args[1].strip()
    wait_msg = await message.answer(
        f"🔍 <b>{target}</b> üçün IP sorğusu...",
        parse_mode="HTML"
    )

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, ip_scanner.scan, target)

    await wait_msg.delete()

    if result["status"] == "error":
        await message.answer(
            f"❌ <b>Xəta:</b> <code>{result['error']}</code>",
            parse_mode="HTML"
        )
        return

    text = (
        f"🌐 <b>IP Intelligence</b>\n"
        f"{'─' * 28}\n"
        f"📡 IP: <code>{result['ip']}</code>\n"
        f"🖥 Hostname: <code>{result['hostname']}</code>"
    )

    await message.answer(text, parse_mode="HTML")
