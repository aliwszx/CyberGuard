from aiogram import Router, types
from aiogram.filters import Command
import asyncio
import logging

from backend.services.scanner_service import ScannerService
from backend.app.services.user_service import UserService
from backend.scanners.whois_scanner import WhoisScanner
from backend.scanners.ip_scanner import IPScanner

logger = logging.getLogger(**name**)

router = Router()

scanner = ScannerService()
user_service = UserService()

whois_scanner = WhoisScanner()
ip_scanner = IPScanner()

# =========================

# START

# =========================

@router.message(Command("start"))
async def start(message: types.Message):

```
user = await user_service.get_or_create_user(
    telegram_id=str(message.from_user.id),
    username=message.from_user.username
)

await message.answer(
    "🛡 <b>CyberGuard Bot</b>\n\n"
    "Mövcud əmrlər:\n"
    "/scan domain.com\n"
    "/whois domain.com\n"
    "/ipintel domain.com\n\n"
    f"👤 User ID: <code>{user.id}</code>",
    parse_mode="HTML"
)
```

# =========================

# WHOIS

# =========================

@router.message(Command("whois"))
async def whois_cmd(message: types.Message):

```
args = message.text.split()

if len(args) < 2:
    await message.answer(
        "❌ İstifadə:\n<code>/whois google.com</code>",
        parse_mode="HTML"
    )
    return

domain = args[1].strip()

wait_msg = await message.answer(
    f"🔍 <b>{domain}</b> üçün WHOIS sorğusu...",
    parse_mode="HTML"
)

try:
    loop = asyncio.get_running_loop()

    result = await loop.run_in_executor(
        None,
        whois_scanner.scan,
        domain
    )

    await wait_msg.delete()

    if result.get("status") == "error":
        await message.answer(
            f"❌ Xəta:\n<code>{result.get('error')}</code>",
            parse_mode="HTML"
        )
        return

    text = (
        "🌍 <b>WHOIS Məlumatı</b>\n\n"
        f"🌐 Domain: <code>{result.get('domain')}</code>\n"
        f"🏢 Registrar: <code>{result.get('registrar') or 'N/A'}</code>\n"
        f"📅 Creation: <code>{result.get('creation_date') or 'N/A'}</code>\n"
        f"⏳ Expiration: <code>{result.get('expiration_date') or 'N/A'}</code>\n"
        f"🖧 Nameservers: <code>{result.get('name_servers') or 'N/A'}</code>"
    )

    await message.answer(text, parse_mode="HTML")

except Exception as e:

    logger.exception("WHOIS ERROR")

    try:
        await wait_msg.delete()
    except:
        pass

    await message.answer(
        f"❌ Xəta:\n<code>{str(e)}</code>",
        parse_mode="HTML"
    )
```

# =========================

# IP INTEL

# =========================

@router.message(Command("ipintel"))
async def ipintel_cmd(message: types.Message):

```
args = message.text.split()

if len(args) < 2:
    await message.answer(
        "❌ İstifadə:\n<code>/ipintel google.com</code>",
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

    await wait_msg.delete()

    if result.get("status") == "error":
        await message.answer(
            f"❌ Xəta:\n<code>{result.get('error')}</code>",
            parse_mode="HTML"
        )
        return

    text = (
        "🌐 <b>IP Intelligence</b>\n\n"
        f"📡 IP: <code>{result.get('ip')}</code>\n"
        f"🖥 Hostname: <code>{result.get('hostname')}</code>"
    )

    await message.answer(text, parse_mode="HTML")

except Exception as e:

    logger.exception("IPINTEL ERROR")

    try:
        await wait_msg.delete()
    except:
        pass

    await message.answer(
        f"❌ Xəta:\n<code>{str(e)}</code>",
        parse_mode="HTML"
    )
```

# =========================

# SCAN

# =========================

@router.message(Command("scan"))
async def scan_cmd(message: types.Message):

```
args = message.text.split()

if len(args) < 2:
    await message.answer(
        "❌ İstifadə:\n<code>/scan google.com</code>",
        parse_mode="HTML"
    )
    return

domain = args[1].strip()

wait_msg = await message.answer(
    f"🔍 <b>{domain}</b> analiz edilir...",
    parse_mode="HTML"
)

try:

    result = await scanner.full_scan_async(domain)

    await wait_msg.delete()

    ssl = result.get("ssl", {})
    tech = result.get("technology", {})
    headers = result.get("headers", {})

    text = (
        f"🛡 <b>CyberGuard Scan</b>\n\n"
        f"🌐 Domain: <code>{domain}</code>\n\n"
        f"🔒 SSL: <code>{ssl.get('ssl_status', 'unknown')}</code>\n"
        f"🧠 Server: <code>{tech.get('server', 'unknown')}</code>\n"
        f"⚠️ Header Risk: <code>{headers.get('risk', 'unknown')}</code>"
    )

    await message.answer(text, parse_mode="HTML")

except Exception as e:

    logger.exception("SCAN ERROR")

    try:
        await wait_msg.delete()
    except:
        pass

    await message.answer(
        f"❌ Scan xətası:\n<code>{str(e)}</code>",
        parse_mode="HTML"
    )
```
