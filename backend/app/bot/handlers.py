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
from backend.scanners.ssl_scanner import SSLScanner
from backend.scanners.tech_detector import TechDetector
from backend.scanners.advanced_port_scanner import AdvancedPortScanner

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
ssl_scanner = SSLScanner()
tech_detector = TechDetector()
port_scanner = AdvancedPortScanner()

# =========================
# START
# =========================

@router.message(Command("ssl"))
async def ssl_cmd(message: types.Message):
    args = message.text.split()

    if len(args) < 2:
        await message.answer(
            "❌ İstifadə:\n<code>/ssl google.com</code>",
            parse_mode="HTML"
        )
        return

    domain = args[1].strip()

    wait_msg = await message.answer(
        f"🔒 <b>{domain}</b> SSL yoxlanılır...",
        parse_mode="HTML"
    )

    try:
        loop = asyncio.get_running_loop()

        result = await loop.run_in_executor(
            None,
            ssl_scanner.scan,
            domain
        )

        await wait_msg.delete()

        status_icon = "✅" if result.get("valid") else "❌"

        text = (
            f"🔒 <b>SSL Report</b>\n\n"
            f"🌐 Domain: <code>{domain}</code>\n\n"
            f"{status_icon} Status: <b>{result.get('ssl_status')}</b>\n"
            f"🔐 TLS: <code>{result.get('tls_version') or 'Unknown'}</code>\n"
            f"🏢 Issuer: <code>{result.get('issuer')}</code>\n"
            f"📅 Expires: <code>{result.get('expires')}</code>"
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

@router.message(Command("tech"))
async def tech_cmd(message: types.Message):
    args = message.text.split()

    if len(args) < 2:
        await message.answer(
            "❌ İstifadə:\n<code>/tech google.com</code>",
            parse_mode="HTML"
        )
        return

    domain = args[1].strip()

    wait_msg = await message.answer(
        f"🧠 <b>{domain}</b> texnologiyaları aşkarlanır...",
        parse_mode="HTML"
    )

    try:
        loop = asyncio.get_running_loop()

        result = await loop.run_in_executor(
            None,
            tech_detector.scan,
            domain
        )

        await wait_msg.delete()

        text = (
            f"🧠 <b>Technology Detection</b>\n\n"
            f"🌐 Domain: <code>{domain}</code>\n\n"
            f"🖥 Server: <code>{result.get('server') or 'Unknown'}</code>\n"
            f"⚙️ Framework: <code>{result.get('framework') or 'Unknown'}</code>\n"
            f"📰 CMS: <code>{result.get('cms') or 'Unknown'}</code>\n"
            f"☁️ CDN: <code>{result.get('cdn') or 'Unknown'}</code>"
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

@router.message(Command("ports"))
async def ports_cmd(message: types.Message):
    args = message.text.split()

    if len(args) < 2:
        await message.answer(
            "❌ İstifadə:\n<code>/ports google.com</code>",
            parse_mode="HTML"
        )
        return

    domain = args[1].strip()

    wait_msg = await message.answer(
        f"🔌 <b>{domain}</b> portları yoxlanılır...",
        parse_mode="HTML"
    )

    try:
        loop = asyncio.get_running_loop()

        result = await loop.run_in_executor(
            None,
            port_scanner.scan,
            domain
        )

        await wait_msg.delete()

        if result.get("error"):
            await message.answer(
                f"❌ <code>{result['error']}</code>",
                parse_mode="HTML"
            )
            return

        ports = result.get("open_ports", [])

        if not ports:
            await message.answer(
                "✅ Açıq port tapılmadı.",
                parse_mode="HTML"
            )
            return

        text = (
            f"🔌 <b>Port Scan</b>\n\n"
            f"🌐 IP: <code>{result['ip']}</code>\n"
            f"⚠️ Risk: <b>{result['risk'].upper()}</b>\n\n"
        )

        for p in ports[:25]:
            service = p.get("service", "Unknown")

            text += (
                f"• <code>{p['port']}</code> "
                f"{service}\n"
            )

        if len(ports) > 25:
            text += (
                f"\n... və daha "
                f"{len(ports)-25} açıq port."
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
