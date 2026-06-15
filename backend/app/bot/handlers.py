from aiogram import Router, types
from aiogram.filters import Command
import asyncio
import logging

from backend.services.scanner_service import ScannerService
from backend.app.services.user_service import UserService
from backend.scanners.whois_scanner import WhoisScanner
from backend.scanners.ip_scanner import IPScanner
from backend.scanners.geoip_scanner import GeoIPScanner
from backend.scanners.dns_scanner import DNSScanner
from backend.scanners.subdomain_scanner import SubdomainScanner
from backend.scanners.header_scanner import HeaderScanner

logger = logging.getLogger(__name__)

router = Router()

scanner = ScannerService()
user_service = UserService()

whois_scanner = WhoisScanner()
ip_scanner = IPScanner()
geoip_scanner = GeoIPScanner()
dns_scanner = DNSScanner()
subdomain_scanner = SubdomainScanner()
header_scanner = HeaderScanner()

# =========================
# START
# =========================

@router.message(Command("start"))
async def start(message: types.Message):
    user = await user_service.get_or_create_user(
        telegram_id=str(message.from_user.id),
        username=message.from_user.username
    )

    await message.answer(
        "🛡 <b>CyberGuard Bot</b>\n\n"
        "Mövcud əmrlər:\n"
        "/scan domain.com\n"
        "/whois domain.com\n"
        "/ipintel domain.com\n"
        "/help\n\n"
        f"👤 User ID: <code>{user.id}</code>",
        parse_mode="HTML"
    )

# =========================
# HELP
# =========================

@router.message(Command("help"))
async def help_cmd(message: types.Message):
    text = (
        "🛡 <b>CyberGuard Help</b>\n\n"

        "📌 Mövcud əmrlər:\n\n"

        "🔍 <b>/scan domain.com</b>\n"
        "Domain üzrə tam təhlükəsizlik analizi.\n\n"

        "🌍 <b>/whois domain.com</b>\n"
        "WHOIS məlumatlarını göstərir.\n\n"

        "🌐 <b>/ipintel domain.com</b>\n"
        "IP və hostname məlumatlarını göstərir.\n\n"

        "🌍 <b>/geoip ip və ya domain</b>\n"
        "IP geolokasiya məlumatları"

        "❓ <b>/help</b>\n"
        "Bu kömək menyusunu göstərir.\n\n"

        "Nümunələr:\n"
        "<code>/scan google.com</code>\n"
        "<code>/whois google.com</code>\n"
        "<code>/ipintel google.com</code>"
    )

    await message.answer(text, parse_mode="HTML")
    
# =========================
# WHOIS
# =========================

@router.message(Command("whois"))
async def whois_cmd(message: types.Message):
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
        except Exception:
            pass

        await message.answer(
            f"❌ Xəta:\n<code>{str(e)}</code>",
            parse_mode="HTML"
        )


# =========================
# IP INTEL
# =========================

@router.message(Command("ipintel"))
async def ipintel_cmd(message: types.Message):
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
        except Exception:
            pass

        await message.answer(
            f"❌ Xəta:\n<code>{str(e)}</code>",
            parse_mode="HTML"
        )

@router.message(Command("geoip"))
async def geoip_cmd(message: types.Message):
    args = message.text.split()

    if len(args) < 2:
        await message.answer(
            "❌ İstifadə:\n<code>/geoip 8.8.8.8</code>",
            parse_mode="HTML"
        )
        return

    target = args[1].strip()

    wait_msg = await message.answer(
        f"🌍 <b>{target}</b> üçün GeoIP məlumatları yoxlanılır...",
        parse_mode="HTML"
    )

    try:
        loop = asyncio.get_running_loop()

        result = await loop.run_in_executor(
            None,
            geoip_scanner.scan,
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
            "🌍 <b>GeoIP Məlumatı</b>\n\n"
            f"📡 IP: <code>{result.get('ip')}</code>\n"
            f"🏳️ Ölkə: <code>{result.get('country')}</code>\n"
            f"🏙 Şəhər: <code>{result.get('city')}</code>\n"
            f"🏢 ISP: <code>{result.get('isp')}</code>\n"
            f"🌐 ASN: <code>{result.get('asn')}</code>\n"
            f"🕒 Timezone: <code>{result.get('timezone')}</code>"
        )

        await message.answer(text, parse_mode="HTML")

    except Exception as e:
        try:
            await wait_msg.delete()
        except Exception:
            pass

        await message.answer(
            f"❌ Xəta:\n<code>{str(e)}</code>",
            parse_mode="HTML"
        )

@router.message(Command("dns"))
async def dns_cmd(message: types.Message):
    args = message.text.split()

    if len(args) < 2:
        await message.answer(
            "❌ İstifadə:\n<code>/dns google.com</code>",
            parse_mode="HTML"
        )
        return

    domain = args[1].strip()

    wait_msg = await message.answer(
        f"🔍 <b>{domain}</b> DNS məlumatları yoxlanılır...",
        parse_mode="HTML"
    )

    try:
        loop = asyncio.get_running_loop()

        result = await loop.run_in_executor(
            None,
            dns_scanner.scan,
            domain
        )

        await wait_msg.delete()

        if result["status"] == "error":
            await message.answer(
                f"❌ Xəta:\n<code>{result['error']}</code>",
                parse_mode="HTML"
            )
            return

        dns_data = result["dns"]

        def fmt(items):
            return "\n".join(items[:5]) if items else "Yoxdur"

        text = (
            f"🌍 <b>DNS Məlumatları</b>\n\n"
            f"🌐 Domain: <code>{domain}</code>\n\n"
            f"<b>A</b>\n<code>{fmt(dns_data['A'])}</code>\n\n"
            f"<b>AAAA</b>\n<code>{fmt(dns_data['AAAA'])}</code>\n\n"
            f"<b>MX</b>\n<code>{fmt(dns_data['MX'])}</code>\n\n"
            f"<b>NS</b>\n<code>{fmt(dns_data['NS'])}</code>\n\n"
            f"<b>TXT</b>\n<code>{fmt(dns_data['TXT'])}</code>"
        )

        await message.answer(text, parse_mode="HTML")

    except Exception as e:
        try:
            await wait_msg.delete()
        except Exception:
            pass

        await message.answer(
            f"❌ Xəta:\n<code>{str(e)}</code>",
            parse_mode="HTML"
        )
# =========================
# SCAN
# =========================

@router.message(Command("scan"))
async def scan_cmd(message: types.Message):
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
        except Exception:
            pass

        await message.answer(
            f"❌ Scan xətası:\n<code>{str(e)}</code>",
            parse_mode="HTML"
        )

@router.message(Command("subdomains"))
async def subdomains_cmd(message: types.Message):
    args = message.text.split()

    if len(args) < 2:
        await message.answer(
            "❌ İstifadə:\n<code>/subdomains google.com</code>",
            parse_mode="HTML"
        )
        return

    domain = args[1].strip().lower()

    wait_msg = await message.answer(
        f"🔍 <b>{domain}</b> üçün subdomainlər axtarılır...",
        parse_mode="HTML"
    )

    try:
        loop = asyncio.get_running_loop()

        result = await loop.run_in_executor(
            None,
            subdomain_scanner.scan,
            domain
        )

        await wait_msg.delete()

        if result["status"] == "error":
            await message.answer(
                f"❌ Xəta:\n<code>{result['error']}</code>",
                parse_mode="HTML"
            )
            return

        subs = result["subdomains"]

        if not subs:
            await message.answer(
                f"⚠️ <b>{domain}</b> üçün subdomain tapılmadı.",
                parse_mode="HTML"
            )
            return

        preview = "\n".join(
            f"• <code>{sub}</code>"
            for sub in subs[:50]
        )

        text = (
            f"🌐 <b>Subdomain Kəşfiyyatı</b>\n\n"
            f"🎯 Domain: <code>{domain}</code>\n"
            f"📊 Tapıldı: <b>{result['count']}</b>\n\n"
            f"{preview}"
        )

        if len(subs) > 50:
            text += (
                f"\n\n⚠️ Daha {len(subs)-50} subdomain mövcuddur."
            )

        await message.answer(
            text,
            parse_mode="HTML"
        )

    except Exception as e:
        try:
            await wait_msg.delete()
        except Exception:
            pass

        await message.answer(
            f"❌ Xəta:\n<code>{str(e)}</code>",
            parse_mode="HTML"
        )

@router.message(Command("headers"))
async def headers_cmd(message: types.Message):
    args = message.text.split()

    if len(args) < 2:
        await message.answer(
            "❌ İstifadə:\n<code>/headers google.com</code>",
            parse_mode="HTML"
        )
        return

    domain = args[1].strip()

    wait_msg = await message.answer(
        f"🔍 <b>{domain}</b> HTTP başlıqları yoxlanılır...",
        parse_mode="HTML"
    )

    try:
        loop = asyncio.get_running_loop()

        result = await loop.run_in_executor(
            None,
            header_scanner.scan,
            domain
        )

        await wait_msg.delete()

        if result["status"] == "error":
            await message.answer(
                f"❌ Xəta:\n<code>{result['error']}</code>",
                parse_mode="HTML"
            )
            return

        risk = result["risk"]

        risk_icon = {
            "low": "🟢",
            "medium": "🟡",
            "high": "🔴"
        }.get(risk, "⚪")

        present_text = "\n".join(
            f"✅ {h}"
            for h in result["present"].keys()
        )

        missing_text = "\n".join(
            f"❌ {h}"
            for h in result["missing"]
        )

        if not present_text:
            present_text = "—"

        if not missing_text:
            missing_text = "Yoxdur"

        text = (
            f"🔒 <b>HTTP Security Headers</b>\n\n"
            f"🌐 Domain: <code>{domain}</code>\n\n"
            f"{risk_icon} Risk: <b>{risk.upper()}</b>\n\n"
            f"<b>Mövcud:</b>\n"
            f"{present_text}\n\n"
            f"<b>Çatışmayan:</b>\n"
            f"{missing_text}"
        )

        await message.answer(
            text,
            parse_mode="HTML"
        )

    except Exception as e:
        try:
            await wait_msg.delete()
        except Exception:
            pass

        await message.answer(
            f"❌ Xəta:\n<code>{str(e)}</code>",
            parse_mode="HTML"
        )
