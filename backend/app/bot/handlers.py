"""
CyberGuard Bot — Command Router
Bütün Telegram bot əmrlərini idarə edir.
"""

from __future__ import annotations

import asyncio
import logging
from functools import wraps
from typing import Any, Callable

from aiogram import Router, types
from aiogram.filters import Command

from backend.app.services.user_service import UserService
from backend.scanners.dns_scanner import DNSScanner
from backend.scanners.geoip_scanner import GeoIPScanner
from backend.scanners.header_scanner import HeaderScanner
from backend.scanners.ip_scanner import IPScanner
from backend.scanners.subdomain_scanner import SubdomainScanner
from backend.scanners.whois_scanner import WhoisScanner
from backend.services.scanner_service import ScannerService

logger = logging.getLogger(__name__)

router = Router()

# ---------------------------------------------------------------------------
# Singleton servis instansiyaları
# ---------------------------------------------------------------------------

_scanner = ScannerService()
_user_service = UserService()
_whois = WhoisScanner()
_ip = IPScanner()
_geoip = GeoIPScanner()
_dns = DNSScanner()
_subdomain = SubdomainScanner()
_header = HeaderScanner()

# ---------------------------------------------------------------------------
# Yardımçı funksiyalar
# ---------------------------------------------------------------------------

MAX_SUBDOMAIN_PREVIEW = 50
RISK_ICONS: dict[str, str] = {"low": "🟢", "medium": "🟡", "high": "🔴"}


async def _run_sync(func: Callable, *args: Any) -> Any:
    """Sinxron scanner metodunu asinxron executor-da işlədir."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, func, *args)


def _get_domain(message: types.Message, usage_example: str) -> str | None:
    """
    Mesajdan domain/IP arqumentini oxuyur.
    Arqument yoxdursa istifadəçiyə xəta mesajı göndərir və None qaytarır.
    """
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip():
        return None
    return args[1].strip()


async def _send_usage_error(message: types.Message, example: str) -> None:
    await message.answer(
        f"❌ <b>İstifadə qaydası:</b>\n<code>{example}</code>",
        parse_mode="HTML",
    )


def _fmt_list(items: list[str], limit: int = 5) -> str:
    """Siyahını formatlanmış mətnə çevirir."""
    if not items:
        return "—"
    return "\n".join(items[:limit])


def with_wait_message(loading_text_template: str):
    """
    Dekorator: handler işləyərkən "yüklənir..." mesajı göstərir,
    tamamlandıqda və ya xəta olduqda siliir.
    """
    def decorator(handler: Callable):
        @wraps(handler)
        async def wrapper(message: types.Message, *args, **kwargs):
            domain_args = message.text.split(maxsplit=1)
            target = domain_args[1].strip() if len(domain_args) > 1 else "..."
            wait_msg = await message.answer(
                loading_text_template.format(target=target),
                parse_mode="HTML",
            )
            try:
                await handler(message, wait_msg, *args, **kwargs)
            except Exception as exc:
                logger.exception("Handler xətası: %s", handler.__name__)
                await message.answer(
                    f"❌ <b>Gözlənilməz xəta:</b>\n<code>{exc}</code>",
                    parse_mode="HTML",
                )
            finally:
                try:
                    await wait_msg.delete()
                except Exception:
                    pass
        return wrapper
    return decorator


async def _handle_scan_error(
    message: types.Message,
    wait_msg: types.Message,
    result: dict,
) -> bool:
    """
    Nəticədə xəta varsa istifadəçiyə bildirir.
    Xəta varsa True, yoxsa False qaytarır.
    """
    if result.get("status") == "error":
        await wait_msg.delete()
        await message.answer(
            f"❌ <b>Xəta:</b>\n<code>{result.get('error', 'Naməlum xəta')}</code>",
            parse_mode="HTML",
        )
        return True
    return False


# ---------------------------------------------------------------------------
# /start
# ---------------------------------------------------------------------------

@router.message(Command("start"))
async def cmd_start(message: types.Message) -> None:
    user = await _user_service.get_or_create_user(
        telegram_id=str(message.from_user.id),
        username=message.from_user.username,
    )
    await message.answer(
        "🛡 <b>CyberGuard Bot</b> — Kibertəhlükəsizlik Analiz Aləti\n\n"
        "📋 <b>Mövcud əmrlər:</b>\n"
        "  /scan <i>domain.com</i> — Tam təhlükəsizlik analizi\n"
        "  /whois <i>domain.com</i> — WHOIS məlumatları\n"
        "  /ipintel <i>domain.com</i> — IP kəşfiyyatı\n"
        "  /geoip <i>ip/domain</i> — Coğrafi məkan\n"
        "  /dns <i>domain.com</i> — DNS qeydləri\n"
        "  /subdomains <i>domain.com</i> — Subdomain kəşfiyyatı\n"
        "  /headers <i>domain.com</i> — HTTP başlıq analizi\n"
        "  /help — Ətraflı kömək\n\n"
        f"👤 İstifadəçi ID: <code>{user.id}</code>",
        parse_mode="HTML",
    )


# ---------------------------------------------------------------------------
# /help
# ---------------------------------------------------------------------------

@router.message(Command("help"))
async def cmd_help(message: types.Message) -> None:
    await message.answer(
        "🛡 <b>CyberGuard — Kömək Menyusu</b>\n\n"
        "🔍 <b>/scan</b> <code>domain.com</code>\n"
        "   SSL, server texnologiyası və başlıq risklərini analiz edir.\n\n"
        "🌍 <b>/whois</b> <code>domain.com</code>\n"
        "   Registrar, yaradılma/bitmə tarixi və nameserver məlumatları.\n\n"
        "🌐 <b>/ipintel</b> <code>domain.com</code>\n"
        "   IP ünvanı və hostname axtarışı.\n\n"
        "📍 <b>/geoip</b> <code>8.8.8.8</code>\n"
        "   IP-nin ölkə, şəhər, ISP və ASN məlumatları.\n\n"
        "🗂 <b>/dns</b> <code>domain.com</code>\n"
        "   A, AAAA, MX, NS, TXT qeydlərini göstərir.\n\n"
        "🔎 <b>/subdomains</b> <code>domain.com</code>\n"
        "   Passiv subdomain kəşfiyyatı aparır.\n\n"
        "🔒 <b>/headers</b> <code>domain.com</code>\n"
        "   HTTP təhlükəsizlik başlıqlarını yoxlayır.\n\n"
        "💡 <b>Nümunələr:</b>\n"
        "<code>/scan google.com</code>\n"
        "<code>/geoip 1.1.1.1</code>\n"
        "<code>/subdomains tesla.com</code>",
        parse_mode="HTML",
    )


# ---------------------------------------------------------------------------
# /whois
# ---------------------------------------------------------------------------

@router.message(Command("whois"))
@with_wait_message("🔍 <b>{target}</b> üçün WHOIS sorğusu göndərilir...")
async def cmd_whois(message: types.Message, wait_msg: types.Message) -> None:
    domain = _get_domain(message, "/whois google.com")
    if not domain:
        await _send_usage_error(message, "/whois google.com")
        return

    result = await _run_sync(_whois.scan, domain)
    if await _handle_scan_error(message, wait_msg, result):
        return

    await wait_msg.delete()
    await message.answer(
        "🌍 <b>WHOIS Məlumatı</b>\n\n"
        f"🌐 Domain:     <code>{result.get('domain', '—')}</code>\n"
        f"🏢 Registrar:  <code>{result.get('registrar') or '—'}</code>\n"
        f"📅 Yaradıldı:  <code>{result.get('creation_date') or '—'}</code>\n"
        f"⏳ Bitmə:      <code>{result.get('expiration_date') or '—'}</code>\n"
        f"🖧 Nameserver: <code>{result.get('name_servers') or '—'}</code>",
        parse_mode="HTML",
    )


# ---------------------------------------------------------------------------
# /ipintel
# ---------------------------------------------------------------------------

@router.message(Command("ipintel"))
@with_wait_message("🌐 <b>{target}</b> üçün IP kəşfiyyatı aparılır...")
async def cmd_ipintel(message: types.Message, wait_msg: types.Message) -> None:
    target = _get_domain(message, "/ipintel google.com")
    if not target:
        await _send_usage_error(message, "/ipintel google.com")
        return

    result = await _run_sync(_ip.scan, target)
    if await _handle_scan_error(message, wait_msg, result):
        return

    await wait_msg.delete()
    await message.answer(
        "🌐 <b>IP Intelligence</b>\n\n"
        f"📡 IP:       <code>{result.get('ip', '—')}</code>\n"
        f"🖥 Hostname: <code>{result.get('hostname', '—')}</code>",
        parse_mode="HTML",
    )


# ---------------------------------------------------------------------------
# /geoip
# ---------------------------------------------------------------------------

@router.message(Command("geoip"))
@with_wait_message("📍 <b>{target}</b> üçün GeoIP məlumatları alınır...")
async def cmd_geoip(message: types.Message, wait_msg: types.Message) -> None:
    target = _get_domain(message, "/geoip 8.8.8.8")
    if not target:
        await _send_usage_error(message, "/geoip 8.8.8.8")
        return

    result = await _run_sync(_geoip.scan, target)
    if await _handle_scan_error(message, wait_msg, result):
        return

    await wait_msg.delete()
    await message.answer(
        "📍 <b>GeoIP Məlumatı</b>\n\n"
        f"📡 IP:       <code>{result.get('ip', '—')}</code>\n"
        f"🏳️ Ölkə:    <code>{result.get('country', '—')}</code>\n"
        f"🏙 Şəhər:   <code>{result.get('city', '—')}</code>\n"
        f"🏢 ISP:     <code>{result.get('isp', '—')}</code>\n"
        f"🌐 ASN:     <code>{result.get('asn', '—')}</code>\n"
        f"🕒 Timezone: <code>{result.get('timezone', '—')}</code>",
        parse_mode="HTML",
    )


# ---------------------------------------------------------------------------
# /dns
# ---------------------------------------------------------------------------

@router.message(Command("dns"))
@with_wait_message("🗂 <b>{target}</b> DNS qeydləri sorğulanır...")
async def cmd_dns(message: types.Message, wait_msg: types.Message) -> None:
    domain = _get_domain(message, "/dns google.com")
    if not domain:
        await _send_usage_error(message, "/dns google.com")
        return

    result = await _run_sync(_dns.scan, domain)
    if await _handle_scan_error(message, wait_msg, result):
        return

    dns = result.get("dns", {})
    await wait_msg.delete()
    await message.answer(
        f"🗂 <b>DNS Qeydləri</b>\n\n"
        f"🌐 Domain: <code>{domain}</code>\n\n"
        f"<b>A</b>\n<code>{_fmt_list(dns.get('A', []))}</code>\n\n"
        f"<b>AAAA</b>\n<code>{_fmt_list(dns.get('AAAA', []))}</code>\n\n"
        f"<b>MX</b>\n<code>{_fmt_list(dns.get('MX', []))}</code>\n\n"
        f"<b>NS</b>\n<code>{_fmt_list(dns.get('NS', []))}</code>\n\n"
        f"<b>TXT</b>\n<code>{_fmt_list(dns.get('TXT', []))}</code>",
        parse_mode="HTML",
    )


# ---------------------------------------------------------------------------
# /subdomains
# ---------------------------------------------------------------------------

@router.message(Command("subdomains"))
@with_wait_message("🔎 <b>{target}</b> üçün subdomainlər axtarılır...")
async def cmd_subdomains(message: types.Message, wait_msg: types.Message) -> None:
    domain = _get_domain(message, "/subdomains google.com")
    if not domain:
        await _send_usage_error(message, "/subdomains google.com")
        return

    result = await _run_sync(_subdomain.scan, domain.lower())
    if await _handle_scan_error(message, wait_msg, result):
        return

    subs: list[str] = result.get("subdomains", [])
    total: int = result.get("count", len(subs))

    await wait_msg.delete()

    if not subs:
        await message.answer(
            f"⚠️ <b>{domain}</b> üçün heç bir subdomain tapılmadı.",
            parse_mode="HTML",
        )
        return

    preview = "\n".join(f"• <code>{s}</code>" for s in subs[:MAX_SUBDOMAIN_PREVIEW])
    overflow = f"\n\n➕ Daha <b>{total - MAX_SUBDOMAIN_PREVIEW}</b> subdomain mövcuddur." if total > MAX_SUBDOMAIN_PREVIEW else ""

    await message.answer(
        f"🔎 <b>Subdomain Kəşfiyyatı</b>\n\n"
        f"🎯 Domain: <code>{domain}</code>\n"
        f"📊 Cəmi tapıldı: <b>{total}</b>\n\n"
        f"{preview}{overflow}",
        parse_mode="HTML",
    )


# ---------------------------------------------------------------------------
# /headers
# ---------------------------------------------------------------------------

@router.message(Command("headers"))
@with_wait_message("🔒 <b>{target}</b> HTTP başlıqları analiz edilir...")
async def cmd_headers(message: types.Message, wait_msg: types.Message) -> None:
    domain = _get_domain(message, "/headers google.com")
    if not domain:
        await _send_usage_error(message, "/headers google.com")
        return

    result = await _run_sync(_header.scan, domain)
    if await _handle_scan_error(message, wait_msg, result):
        return

    risk: str = result.get("risk", "unknown")
    icon: str = RISK_ICONS.get(risk, "⚪")

    present_text = "\n".join(f"✅ <code>{h}</code>" for h in result.get("present", {}).keys()) or "—"
    missing_text = "\n".join(f"❌ <code>{h}</code>" for h in result.get("missing", [])) or "✅ Hamısı mövcuddur"

    await wait_msg.delete()
    await message.answer(
        f"🔒 <b>HTTP Security Headers</b>\n\n"
        f"🌐 Domain: <code>{domain}</code>\n"
        f"{icon} Risk Səviyyəsi: <b>{risk.upper()}</b>\n\n"
        f"<b>Mövcud başlıqlar:</b>\n{present_text}\n\n"
        f"<b>Çatışmayan başlıqlar:</b>\n{missing_text}",
        parse_mode="HTML",
    )


# ---------------------------------------------------------------------------
# /scan
# ---------------------------------------------------------------------------

@router.message(Command("scan"))
@with_wait_message("🛡 <b>{target}</b> üzrə tam təhlükəsizlik analizi aparılır...")
async def cmd_scan(message: types.Message, wait_msg: types.Message) -> None:
    domain = _get_domain(message, "/scan google.com")
    if not domain:
        await _send_usage_error(message, "/scan google.com")
        return

    result = await _scanner.full_scan_async(domain)

    ssl = result.get("ssl", {})
    tech = result.get("technology", {})
    headers = result.get("headers", {})

    ssl_status = ssl.get("ssl_status", "unknown")
    ssl_icon = "🔒" if ssl_status == "valid" else "🔓"

    risk = headers.get("risk", "unknown")
    risk_icon = RISK_ICONS.get(risk, "⚪")

    await wait_msg.delete()
    await message.answer(
        f"🛡 <b>CyberGuard — Tam Analiz</b>\n\n"
        f"🌐 Domain: <code>{domain}</code>\n\n"
        f"{ssl_icon} SSL Statusu:   <code>{ssl_status}</code>\n"
        f"🏷 SSL Emitent:  <code>{ssl.get('issuer', '—')}</code>\n"
        f"📅 SSL Bitmə:    <code>{ssl.get('expiry', '—')}</code>\n\n"
        f"🧠 Server:       <code>{tech.get('server', '—')}</code>\n"
        f"⚙️ Texnologiya:  <code>{tech.get('framework', '—')}</code>\n\n"
        f"{risk_icon} Başlıq Riski: <b>{risk.upper()}</b>",
        parse_mode="HTML",
    )
