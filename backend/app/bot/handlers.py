"""
CyberGuard Bot — Professional Command Router
=============================================
Bütün Telegram bot əmrlərini idarə edir.

Əhatə olunan scanner-lər:
  ✅ WhoisScanner
  ✅ IPScanner
  ✅ GeoIPScanner
  ✅ DNSScanner
  ✅ SSLScanner
  ✅ HeaderScanner
  ✅ TechDetector
  ✅ PortScanner
  ✅ AdvancedPortScanner
  ✅ SubdomainScanner
  ✅ ScannerService (full_scan_async)
"""

from __future__ import annotations

import asyncio
import logging
from functools import wraps
from typing import Any, Callable

from aiogram import F, Router, types
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup

from backend.app.services.user_service import UserService
from backend.scanners.advanced_port_scanner import AdvancedPortScanner
from backend.scanners.dns_scanner import DNSScanner
from backend.scanners.geoip_scanner import GeoIPScanner
from backend.scanners.header_scanner import HeaderScanner
from backend.scanners.ip_scanner import IPScanner
from backend.scanners.ssl_scanner import SSLScanner
from backend.scanners.subdomain_scanner import SubdomainScanner
from backend.scanners.tech_detector import TechDetector
from backend.scanners.whois_scanner import WhoisScanner
from backend.services.scanner_service import ScannerService

logger = logging.getLogger(__name__)

router = Router()

# ─────────────────────────────────────────────────────────────
# Scanner instansiyaları  (module-level singleton-lar)
# ─────────────────────────────────────────────────────────────
_scanner        = ScannerService()
_user_service   = UserService()
_whois          = WhoisScanner()
_ip             = IPScanner()
_geoip          = GeoIPScanner()
_dns            = DNSScanner()
_ssl            = SSLScanner()
_header         = HeaderScanner()
_tech           = TechDetector()
_port           = AdvancedPortScanner()
_subdomain      = SubdomainScanner()

# ─────────────────────────────────────────────────────────────
# Sabitlər
# ─────────────────────────────────────────────────────────────
MAX_SUBDOMAIN_PREVIEW = 50
MAX_MESSAGE_LENGTH    = 4000   # Telegram limiti 4096, ehtiyat üçün 4000

RISK_ICONS: dict[str, str] = {
    "minimal": "🟢",
    "low":     "🟢",
    "medium":  "🟡",
    "high":    "🔴",
    "unknown": "⚪",
}

PORT_STATE_ICONS: dict[str, str] = {
    "open":     "🟢",
    "closed":   "⚫",
    "filtered": "🟡",
    "error":    "🔴",
}

# ─────────────────────────────────────────────────────────────
# FSM — /deepportscan üçün 4 mərhələli interaktiv wizard
# ─────────────────────────────────────────────────────────────
class DeepScan(StatesGroup):
    domain      = State()   # 1) domain daxil et
    mode        = State()   # 2) port rejimi seç (ümumi / xüsusi / aralıq)
    custom_ports = State()  # 3) xüsusi portları daxil et (yalnız "custom" seçilsə)
    speed       = State()   # 4) sürət seç (fast / deep)


# ─────────────────────────────────────────────────────────────
# Klaviatura builder-ları
# ─────────────────────────────────────────────────────────────

def _kb_mode() -> types.ReplyKeyboardMarkup:
    """Port rejimi seçim klaviaturası."""
    return types.ReplyKeyboardMarkup(
        keyboard=[
            [
                types.KeyboardButton(text="🗂 Ümumi portlar"),
                types.KeyboardButton(text="✏️ Xüsusi portlar"),
            ],
            [
                types.KeyboardButton(text="📐 Port aralığı"),
                types.KeyboardButton(text="❌ Ləğv et"),
            ],
        ],
        resize_keyboard=True,
        one_time_keyboard=True,
    )


def _kb_speed() -> types.ReplyKeyboardMarkup:
    """Sürət seçim klaviaturası."""
    return types.ReplyKeyboardMarkup(
        keyboard=[
            [
                types.KeyboardButton(text="⚡ Sürətli (fast)"),
                types.KeyboardButton(text="🔬 Dərin (deep)"),
            ],
            [
                types.KeyboardButton(text="❌ Ləğv et"),
            ],
        ],
        resize_keyboard=True,
        one_time_keyboard=True,
    )


def _kb_remove() -> types.ReplyKeyboardRemove:
    return types.ReplyKeyboardRemove()


# ─────────────────────────────────────────────────────────────
# Köməkçi funksiyalar
# ─────────────────────────────────────────────────────────────

async def _run_sync(func: Callable, *args: Any) -> Any:
    """Bloklayan scanner metodunu thread pool-da asinxron işlədir."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, func, *args)


def _parse_args(message: types.Message) -> list[str]:
    """Mesaj mətni (/cmd arg1 arg2) → [arg1, arg2]"""
    parts = message.text.strip().split()
    return parts[1:]  # əmri çıxarırıq


async def _usage_error(message: types.Message, example: str) -> None:
    await message.answer(
        f"❌ <b>İstifadə qaydası:</b>\n<code>{example}</code>",
        parse_mode="HTML",
    )


def _fmt_list(items: list[str], limit: int = 5) -> str:
    """Siyahı → sətir, boşdursa tire."""
    return "\n".join(items[:limit]) if items else "—"


def _safe_truncate(text: str, limit: int = MAX_MESSAGE_LENGTH) -> str:
    """Telegram mesaj limitini aşmamaq üçün kəs."""
    if len(text) <= limit:
        return text
    return text[:limit] + "\n\n⚠️ <i>Mətn çox uzun olduğu üçün kəsildi.</i>"


def _ssl_issuer_str(issuer: dict | None) -> str:
    """SSL issuer dict-ini oxunaqlı formata çevirir."""
    if not issuer:
        return "—"
    return issuer.get("organizationName") or issuer.get("commonName") or str(issuer)


# ─────────────────────────────────────────────────────────────
# @with_wait_message dekoratoru
# ─────────────────────────────────────────────────────────────
def with_wait_message(template: str):
    """
    Handler işə düşəndə "yüklənir..." mesajı göndərir.
    Handler bitdikdə və ya xəta olduqda mesajı silir.

    Handler imzası:  async def handler(message, wait_msg, *args, **kwargs)
    """
    def decorator(handler: Callable):
        @wraps(handler)
        async def wrapper(message: types.Message, *args, **kwargs):
            raw_args = _parse_args(message)
            target = raw_args[0] if raw_args else "..."
            wait_msg = await message.answer(
                template.format(target=target),
                parse_mode="HTML",
            )
            try:
                await handler(message, wait_msg, *args, **kwargs)
            except Exception as exc:
                logger.exception("Handler xətası [%s]: %s", handler.__name__, exc)
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


async def _check_error(
    message: types.Message,
    wait_msg: types.Message,
    result: dict,
) -> bool:
    """
    Scanner nəticəsini yoxlayır.
    Xəta varsa istifadəçiyə bildirir, True qaytarır.
    """
    if result.get("status") == "error":
        try:
            await wait_msg.delete()
        except Exception:
            pass
        await message.answer(
            f"❌ <b>Xəta:</b>\n<code>{result.get('error', 'Naməlum xəta')}</code>",
            parse_mode="HTML",
        )
        return True
    return False


# ═════════════════════════════════════════════════════════════
# /start
# ═════════════════════════════════════════════════════════════
@router.message(Command("start"))
async def cmd_start(message: types.Message) -> None:
    user = await _user_service.get_or_create_user(
        telegram_id=str(message.from_user.id),
        username=message.from_user.username,
    )
    await message.answer(
        "🛡 <b>CyberGuard Bot</b> — Kibertəhlükəsizlik Analiz Platforması\n\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "📋 <b>Əmrlər siyahısı:</b>\n\n"
        "🔍 /scan <code>domain.com</code> — Tam 6-in-1 analiz\n"
        "🌍 /whois <code>domain.com</code> — WHOIS qeydiyyat məlumatı\n"
        "🌐 /ipintel <code>domain.com</code> — IP və hostname\n"
        "📍 /geoip <code>ip/domain</code> — Coğrafi məkan\n"
        "🗂 /dns <code>domain.com</code> — DNS qeydləri (A/AAAA/MX/NS/TXT)\n"
        "🔒 /ssl <code>domain.com</code> — SSL sertifikat analizi\n"
        "🛡 /headers <code>domain.com</code> — HTTP başlıq təhlükəsizliyi\n"
        "🧠 /tech <code>domain.com</code> — Texnologiya aşkarlanması\n"
        "🔎 /subdomains <code>domain.com</code> — Subdomain kəşfiyyatı\n"
        "⚡ /portscan <code>domain.com</code> — Sürətli port skanı\n"
        "🔬 /deepportscan <code>domain.com</code> — Dərin port + risk analizi\n"
        "❓ /help — Kömək menyusu\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"👤 İstifadəçi ID: <code>{user.id}</code>",
        parse_mode="HTML",
    )


# ═════════════════════════════════════════════════════════════
# /help
# ═════════════════════════════════════════════════════════════
@router.message(Command("help"))
async def cmd_help(message: types.Message) -> None:
    await message.answer(
        "🛡 <b>CyberGuard — Ətraflı Kömək</b>\n\n"

        "🔍 <b>/scan</b> <code>domain.com</code>\n"
        "   DNS + SSL + Headers + Tech + Ports — tam analiz paketi.\n\n"

        "🌍 <b>/whois</b> <code>domain.com</code>\n"
        "   Registrar, yaradılma/bitmə tarixi, nameserver-lər.\n\n"

        "🌐 <b>/ipintel</b> <code>domain.com</code>\n"
        "   IP ünvanı və reverse-DNS hostname axtarışı.\n\n"

        "📍 <b>/geoip</b> <code>8.8.8.8</code>\n"
        "   Ölkə, şəhər, ISP, ASN, timezone məlumatları.\n\n"

        "🗂 <b>/dns</b> <code>domain.com</code>\n"
        "   A, AAAA, MX, NS, TXT qeydlərini göstərir.\n\n"

        "🔒 <b>/ssl</b> <code>domain.com</code>\n"
        "   Sertifikat etibarlılığı, emitent, bitmə tarixi, TLS versiyası.\n\n"

        "🛡 <b>/headers</b> <code>domain.com</code>\n"
        "   6 kritik HTTP başlığının mövcudluğunu yoxlayır, risk səviyyəsi bildirir.\n\n"

        "🧠 <b>/tech</b> <code>domain.com</code>\n"
        "   Server, framework, CMS, CDN aşkarlanması.\n\n"

        "🔎 <b>/subdomains</b> <code>domain.com</code>\n"
        "   crt.sh üzərindən passiv subdomain kəşfiyyatı.\n\n"

        "⚡ <b>/portscan</b> <code>domain.com</code>\n"
        "   17 ümumi portu sürətli skan edir (timeout=1s, 100 thread).\n\n"

        "🔬 <b>/deepportscan</b> <code>domain.com [port_spec]</code>\n"
        "   Dərin port skanı + risk analizi + tövsiyələr.\n"
        "   Nümunə: <code>/deepportscan google.com 80,443,8080</code>\n\n"

        "━━━━━━━━━━━━━━━━━━━━━\n"
        "💡 <b>Nümunələr:</b>\n"
        "<code>/scan github.com</code>\n"
        "<code>/ssl cloudflare.com</code>\n"
        "<code>/deepportscan tesla.com 22,80,443,3306</code>\n"
        "<code>/geoip 1.1.1.1</code>",
        parse_mode="HTML",
    )


# ═════════════════════════════════════════════════════════════
# /whois
# ═════════════════════════════════════════════════════════════
@router.message(Command("whois"))
@with_wait_message("🌍 <b>{target}</b> üçün WHOIS sorğusu göndərilir...")
async def cmd_whois(message: types.Message, wait_msg: types.Message) -> None:
    args = _parse_args(message)
    if not args:
        await _usage_error(message, "/whois google.com")
        return

    domain = args[0]
    result = await _run_sync(_whois.scan, domain)
    if await _check_error(message, wait_msg, result):
        return

    # name_servers list ola bilər
    ns = result.get("name_servers")
    if isinstance(ns, (list, set)):
        ns_str = ", ".join(sorted(ns))
    else:
        ns_str = str(ns) if ns else "—"

    await wait_msg.delete()
    await message.answer(
        "🌍 <b>WHOIS Məlumatı</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 Domain:      <code>{result.get('domain', domain)}</code>\n"
        f"🏢 Registrar:   <code>{result.get('registrar') or '—'}</code>\n"
        f"📅 Yaradıldı:   <code>{result.get('creation_date') or '—'}</code>\n"
        f"⏳ Bitmə tarixi:<code>{result.get('expiration_date') or '—'}</code>\n"
        f"🖧 Nameserver:  <code>{ns_str}</code>",
        parse_mode="HTML",
    )


# ═════════════════════════════════════════════════════════════
# /ipintel
# ═════════════════════════════════════════════════════════════
@router.message(Command("ipintel"))
@with_wait_message("🌐 <b>{target}</b> üçün IP kəşfiyyatı aparılır...")
async def cmd_ipintel(message: types.Message, wait_msg: types.Message) -> None:
    args = _parse_args(message)
    if not args:
        await _usage_error(message, "/ipintel google.com")
        return

    target = args[0]
    result = await _run_sync(_ip.scan, target)
    if await _check_error(message, wait_msg, result):
        return

    await wait_msg.delete()
    await message.answer(
        "🌐 <b>IP Intelligence</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 Hədəf:    <code>{target}</code>\n"
        f"📡 IP:       <code>{result.get('ip', '—')}</code>\n"
        f"🖥 Hostname: <code>{result.get('hostname', '—')}</code>",
        parse_mode="HTML",
    )


# ═════════════════════════════════════════════════════════════
# /geoip
# ═════════════════════════════════════════════════════════════
@router.message(Command("geoip"))
@with_wait_message("📍 <b>{target}</b> üçün GeoIP məlumatları alınır...")
async def cmd_geoip(message: types.Message, wait_msg: types.Message) -> None:
    args = _parse_args(message)
    if not args:
        await _usage_error(message, "/geoip 8.8.8.8")
        return

    target = args[0]
    result = await _run_sync(_geoip.scan, target)
    if await _check_error(message, wait_msg, result):
        return

    await wait_msg.delete()
    await message.answer(
        "📍 <b>GeoIP Məlumatı</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 Hədəf:    <code>{target}</code>\n"
        f"📡 IP:       <code>{result.get('ip', '—')}</code>\n"
        f"🏳️ Ölkə:    <code>{result.get('country', '—')}</code>\n"
        f"🏙 Şəhər:   <code>{result.get('city', '—')}</code>\n"
        f"🏢 ISP:      <code>{result.get('isp', '—')}</code>\n"
        f"🌐 ASN:      <code>{result.get('asn', '—')}</code>\n"
        f"🕒 Timezone: <code>{result.get('timezone', '—')}</code>",
        parse_mode="HTML",
    )


# ═════════════════════════════════════════════════════════════
# /dns
# ═════════════════════════════════════════════════════════════
@router.message(Command("dns"))
@with_wait_message("🗂 <b>{target}</b> DNS qeydləri sorğulanır...")
async def cmd_dns(message: types.Message, wait_msg: types.Message) -> None:
    args = _parse_args(message)
    if not args:
        await _usage_error(message, "/dns google.com")
        return

    domain = args[0]
    result = await _run_sync(_dns.scan, domain)
    if await _check_error(message, wait_msg, result):
        return

    dns = result.get("dns", {})

    await wait_msg.delete()
    await message.answer(
        "🗂 <b>DNS Qeydləri</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 Domain: <code>{domain}</code>\n\n"
        f"<b>🔵 A (IPv4)</b>\n<code>{_fmt_list(dns.get('A', []))}</code>\n\n"
        f"<b>🟣 AAAA (IPv6)</b>\n<code>{_fmt_list(dns.get('AAAA', []))}</code>\n\n"
        f"<b>📧 MX (Mail)</b>\n<code>{_fmt_list(dns.get('MX', []))}</code>\n\n"
        f"<b>🖧 NS (Nameserver)</b>\n<code>{_fmt_list(dns.get('NS', []))}</code>\n\n"
        f"<b>📄 TXT</b>\n<code>{_fmt_list(dns.get('TXT', []), limit=3)}</code>",
        parse_mode="HTML",
    )


# ═════════════════════════════════════════════════════════════
# /ssl  ← YENİ (SSLScanner tam istifadə)
# ═════════════════════════════════════════════════════════════
@router.message(Command("ssl"))
@with_wait_message("🔒 <b>{target}</b> SSL sertifikatı yoxlanılır...")
async def cmd_ssl(message: types.Message, wait_msg: types.Message) -> None:
    args = _parse_args(message)
    if not args:
        await _usage_error(message, "/ssl google.com")
        return

    domain = args[0]
    result = await _run_sync(_ssl.scan, domain)

    # SSLScanner heç vaxt status:error qaytarmır, valid field-i var
    ssl_valid   = result.get("valid", False)
    ssl_status  = result.get("ssl_status", "unknown")
    status_icon = "✅" if ssl_valid else "❌"
    tls_ver     = result.get("tls_version") or "—"
    expires     = result.get("expires") or "—"
    issuer_str  = _ssl_issuer_str(result.get("issuer"))

    # Bitmə tarixi üçün qısa xəbərdarlıq
    warning = ""
    if ssl_valid and expires != "—":
        from datetime import datetime
        try:
            exp_dt = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_dt - datetime.utcnow()).days
            if days_left < 0:
                warning = "\n⛔ <b>Sertifikat müddəti bitib!</b>"
            elif days_left <= 30:
                warning = f"\n⚠️ <b>Diqqət: {days_left} gün ərzində bitir!</b>"
        except Exception:
            pass

    await wait_msg.delete()
    await message.answer(
        "🔒 <b>SSL Sertifikat Analizi</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 Domain:      <code>{domain}</code>\n"
        f"{status_icon} Status:       <b>{ssl_status.upper()}</b>\n"
        f"🏷 Emitent:     <code>{issuer_str}</code>\n"
        f"📅 Bitmə:       <code>{expires}</code>\n"
        f"🔑 TLS versiya: <code>{tls_ver}</code>"
        f"{warning}",
        parse_mode="HTML",
    )


# ═════════════════════════════════════════════════════════════
# /headers
# ═════════════════════════════════════════════════════════════
@router.message(Command("headers"))
@with_wait_message("🛡 <b>{target}</b> HTTP başlıqları analiz edilir...")
async def cmd_headers(message: types.Message, wait_msg: types.Message) -> None:
    args = _parse_args(message)
    if not args:
        await _usage_error(message, "/headers google.com")
        return

    domain = args[0]
    result = await _run_sync(_header.scan, domain)
    if await _check_error(message, wait_msg, result):
        return

    risk      = result.get("risk", "unknown")
    risk_icon = RISK_ICONS.get(risk, "⚪")
    present   = result.get("present", {})
    missing   = result.get("missing", [])

    present_lines = "\n".join(
        f"  ✅ <code>{h}</code>"
        for h in present
    ) or "  —"

    missing_lines = "\n".join(
        f"  ❌ <code>{h}</code>"
        for h in missing
    ) or "  ✅ <i>Hamısı mövcuddur</i>"

    score = len(present)
    total = len(present) + len(missing)

    await wait_msg.delete()
    await message.answer(
        "🛡 <b>HTTP Security Headers</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 Domain:      <code>{domain}</code>\n"
        f"{risk_icon} Risk:         <b>{risk.upper()}</b>\n"
        f"📊 Xal:         <b>{score}/{total}</b> başlıq mövcuddur\n\n"
        f"<b>Mövcud başlıqlar:</b>\n{present_lines}\n\n"
        f"<b>Çatışmayan başlıqlar:</b>\n{missing_lines}",
        parse_mode="HTML",
    )


# ═════════════════════════════════════════════════════════════
# /tech  ← YENİ (TechDetector tam istifadə)
# ═════════════════════════════════════════════════════════════
@router.message(Command("tech"))
@with_wait_message("🧠 <b>{target}</b> texnologiyaları aşkarlanır...")
async def cmd_tech(message: types.Message, wait_msg: types.Message) -> None:
    args = _parse_args(message)
    if not args:
        await _usage_error(message, "/tech google.com")
        return

    domain = args[0]
    result = await _run_sync(_tech.scan, domain)

    # TechDetector heç bir status qaytarmır, sadəcə dict
    server    = result.get("server") or "—"
    framework = result.get("framework") or "—"
    cms       = result.get("cms") or "—"
    cdn       = result.get("cdn") or "—"

    # Heç nə tapılmadıqda xəbər ver
    if all(v == "—" for v in [server, framework, cms, cdn]):
        extra = "\n\n⚠️ <i>Texnologiya məlumatı əldə edilə bilmədi (host cavab vermir ola bilər).</i>"
    else:
        extra = ""

    await wait_msg.delete()
    await message.answer(
        "🧠 <b>Texnologiya Aşkarlanması</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 Domain:     <code>{domain}</code>\n"
        f"🖥 Server:     <code>{server}</code>\n"
        f"⚙️ Framework:  <code>{framework}</code>\n"
        f"📝 CMS:        <code>{cms}</code>\n"
        f"☁️ CDN:        <code>{cdn}</code>"
        f"{extra}",
        parse_mode="HTML",
    )


# ═════════════════════════════════════════════════════════════
# /subdomains
# ═════════════════════════════════════════════════════════════
@router.message(Command("subdomains"))
@with_wait_message("🔎 <b>{target}</b> üçün subdomain kəşfiyyatı aparılır...")
async def cmd_subdomains(message: types.Message, wait_msg: types.Message) -> None:
    args = _parse_args(message)
    if not args:
        await _usage_error(message, "/subdomains google.com")
        return

    domain = args[0].lower()
    result = await _run_sync(_subdomain.scan, domain)
    if await _check_error(message, wait_msg, result):
        return

    subs:  list[str] = result.get("subdomains", [])
    total: int       = result.get("count", len(subs))

    await wait_msg.delete()

    if not subs:
        await message.answer(
            f"⚠️ <b>{domain}</b> üçün heç bir subdomain tapılmadı.\n"
            "<i>Domain gizli saxlanıla bilər və ya crt.sh-də qeyd yoxdur.</i>",
            parse_mode="HTML",
        )
        return

    preview = "\n".join(
        f"  • <code>{s}</code>"
        for s in subs[:MAX_SUBDOMAIN_PREVIEW]
    )
    overflow = (
        f"\n\n➕ <i>Daha <b>{total - MAX_SUBDOMAIN_PREVIEW}</b> subdomain mövcuddur.</i>"
        if total > MAX_SUBDOMAIN_PREVIEW else ""
    )

    text = _safe_truncate(
        "🔎 <b>Subdomain Kəşfiyyatı</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 Domain:       <code>{domain}</code>\n"
        f"📊 Cəmi tapıldı: <b>{total}</b>\n\n"
        f"{preview}{overflow}"
    )
    await message.answer(text, parse_mode="HTML")


# ═════════════════════════════════════════════════════════════
# /portscan  — sürətli (AdvancedPortScanner, speed="fast")
# ═════════════════════════════════════════════════════════════
@router.message(Command("portscan"))
@with_wait_message("⚡ <b>{target}</b> sürətli port skanı aparılır...")
async def cmd_portscan(message: types.Message, wait_msg: types.Message) -> None:
    args = _parse_args(message)
    if not args:
        await _usage_error(message, "/portscan google.com")
        return

    domain     = args[0]
    port_spec  = args[1] if len(args) > 1 else None

    result = await _run_sync(
        _port.scan,
        domain,
        port_spec,   # port_spec
        None,        # port_range
        "fast",      # speed
        False,       # show_all → yalnız açıqları
    )

    if result.get("error"):
        await wait_msg.delete()
        await message.answer(
            f"❌ <b>Xəta:</b>\n<code>{result['error']}</code>",
            parse_mode="HTML",
        )
        return

    open_ports = result.get("open_ports", [])
    risk       = result.get("risk", "unknown")
    risk_icon  = RISK_ICONS.get(risk, "⚪")
    total_scanned = result.get("total_scanned", 0)

    if not open_ports:
        ports_text = "  🔒 <i>Açıq port tapılmadı</i>"
    else:
        ports_text = "\n".join(
            f"  {PORT_STATE_ICONS.get(p['state'], '⚪')} "
            f"<code>{p['port']:<6}</code> "
            f"<b>{p.get('service', 'Unknown')}</b>"
            + (f"  <i>{p['banner'][:40]}</i>" if p.get("banner") else "")
            for p in open_ports
        )

    await wait_msg.delete()
    text = _safe_truncate(
        "⚡ <b>Sürətli Port Skanı</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 Hədəf:          <code>{domain}</code>\n"
        f"📡 IP:             <code>{result.get('ip', '—')}</code>\n"
        f"🔢 Skan edildi:    <b>{total_scanned}</b> port\n"
        f"🟢 Açıq port:      <b>{len(open_ports)}</b>\n"
        f"{risk_icon} Risk:           <b>{risk.upper()}</b>\n\n"
        f"<b>Açıq portlar:</b>\n{ports_text}\n\n"
        "<i>Daha ətraflı analiz üçün /deepportscan istifadə edin.</i>"
    )
    await message.answer(text, parse_mode="HTML")


# ═════════════════════════════════════════════════════════════
# /deepportscan  — 4 mərhələli interaktiv FSM wizard
# ═════════════════════════════════════════════════════════════

# ── Mərhələ 1: /deepportscan əmri — domain soruşur ───────────
@router.message(Command("deepportscan"))
async def cmd_deepportscan_start(message: types.Message, state: FSMContext) -> None:
    await state.clear()

    args = _parse_args(message)

    # Əmrlə birlikdə domain yazılıbsa (məs: /deepportscan google.com) birbaşa
    # növbəti mərhələyə keç, yenidən sormaq lazım deyil.
    if args:
        domain = args[0].strip()
        await state.update_data(domain=domain)
        await state.set_state(DeepScan.mode)
        await message.answer(
            f"🔬 <b>Dərin Port Skanı Sihirbazı</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 Hədəf: <code>{domain}</code>\n\n"
            "📋 <b>Port rejimini seçin:</b>\n\n"
            "  🗂 <b>Ümumi portlar</b> — 17 ən çox istifadə olunan port\n"
            "  ✏️ <b>Xüsusi portlar</b> — özünüz daxil edin (məs: 22,80,443)\n"
            "  📐 <b>Port aralığı</b>   — aralıq (məs: 1-1000)",
            parse_mode="HTML",
            reply_markup=_kb_mode(),
        )
        return

    # Domain yazılmayıbsa soruşaq
    await state.set_state(DeepScan.domain)
    await message.answer(
        "🔬 <b>Dərin Port Skanı Sihirbazı</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n\n"
        "1️⃣  Skan etmək istədiyiniz <b>domain və ya IP</b> ünvanını daxil edin:\n\n"
        "<i>Nümunə: google.com  və ya  192.168.1.1</i>",
        parse_mode="HTML",
        reply_markup=_kb_remove(),
    )


# ── Mərhələ 1 → cavab: domain qəbul et ───────────────────────
@router.message(DeepScan.domain)
async def dscan_got_domain(message: types.Message, state: FSMContext) -> None:
    text = message.text.strip()

    if text == "❌ Ləğv et":
        await _dscan_cancel(message, state)
        return

    if not text or " " in text:
        await message.answer(
            "❌ Düzgün domain/IP daxil edin.\n"
            "<i>Nümunə: google.com</i>",
            parse_mode="HTML",
        )
        return

    domain = text.lower()
    await state.update_data(domain=domain)
    await state.set_state(DeepScan.mode)

    await message.answer(
        f"✅ Hədəf: <code>{domain}</code>\n\n"
        "2️⃣  <b>Port rejimini seçin:</b>\n\n"
        "  🗂 <b>Ümumi portlar</b> — 17 ən çox istifadə olunan port\n"
        "  ✏️ <b>Xüsusi portlar</b> — özünüz daxil edin (məs: 22,80,443)\n"
        "  📐 <b>Port aralığı</b>   — aralıq (məs: 1-1000)",
        parse_mode="HTML",
        reply_markup=_kb_mode(),
    )


# ── Mərhələ 2 → cavab: rejim seçildi ─────────────────────────
@router.message(DeepScan.mode)
async def dscan_got_mode(message: types.Message, state: FSMContext) -> None:
    choice = message.text.strip()

    if choice == "❌ Ləğv et":
        await _dscan_cancel(message, state)
        return

    if choice == "🗂 Ümumi portlar":
        await state.update_data(port_spec=None, port_range=None)
        await state.set_state(DeepScan.speed)
        await message.answer(
            "✅ Rejim: <b>Ümumi portlar</b>\n\n"
            "3️⃣  <b>Skan sürətini seçin:</b>\n\n"
            "  ⚡ <b>Sürətli (fast)</b> — 1s timeout · 100 thread · tez nəticə\n"
            "  🔬 <b>Dərin (deep)</b>   — 3s timeout · 30 thread · daha dəqiq",
            parse_mode="HTML",
            reply_markup=_kb_speed(),
        )

    elif choice == "✏️ Xüsusi portlar":
        await state.update_data(port_range=None)
        await state.set_state(DeepScan.custom_ports)
        await message.answer(
            "✅ Rejim: <b>Xüsusi portlar</b>\n\n"
            "3️⃣  Skan etmək istədiyiniz <b>portları vergüllə</b> daxil edin:\n\n"
            "<i>Nümunə: 22,80,443,3306,8080</i>",
            parse_mode="HTML",
            reply_markup=_kb_remove(),
        )

    elif choice == "📐 Port aralığı":
        await state.update_data(port_spec=None)
        await state.set_state(DeepScan.custom_ports)
        await state.update_data(_range_mode=True)
        await message.answer(
            "✅ Rejim: <b>Port aralığı</b>\n\n"
            "3️⃣  Port <b>aralığını</b> daxil edin:\n\n"
            "<i>Nümunə: 1-1000  və ya  8000-9000</i>",
            parse_mode="HTML",
            reply_markup=_kb_remove(),
        )

    else:
        await message.answer(
            "⬇️ Zəhmət olmasa aşağıdakı düymələrdən birini seçin.",
            reply_markup=_kb_mode(),
        )


# ── Mərhələ 3 → cavab: xüsusi portlar / aralıq ──────────────
@router.message(DeepScan.custom_ports)
async def dscan_got_ports(message: types.Message, state: FSMContext) -> None:
    text = message.text.strip()

    if text == "❌ Ləğv et":
        await _dscan_cancel(message, state)
        return

    data = await state.get_data()
    range_mode = data.get("_range_mode", False)

    if range_mode:
        # Aralıq validasiyası: "start-end"
        parts = text.split("-")
        if len(parts) != 2 or not all(p.strip().isdigit() for p in parts):
            await message.answer(
                "❌ Düzgün aralıq formatı deyil.\n"
                "<i>Nümunə: 1-1000</i>",
                parse_mode="HTML",
            )
            return
        start, end = int(parts[0].strip()), int(parts[1].strip())
        if not (0 < start <= end <= 65535):
            await message.answer(
                "❌ Port aralığı 1-65535 arasında olmalıdır.",
                parse_mode="HTML",
            )
            return
        await state.update_data(port_range=text.replace(" ", ""), port_spec=None)
        mode_label = f"📐 Aralıq: <code>{text}</code>"

    else:
        # Vergüllə ayrılmış portlar validasiyası
        raw_ports = [p.strip() for p in text.split(",") if p.strip()]
        if not raw_ports:
            await message.answer("❌ Port daxil edilmədi.", parse_mode="HTML")
            return
        invalid = [p for p in raw_ports if not p.isdigit() or not (0 < int(p) <= 65535)]
        if invalid:
            await message.answer(
                f"❌ Yanlış port(lar): <code>{', '.join(invalid)}</code>\n"
                "Portlar 1-65535 arasında rəqəm olmalıdır.",
                parse_mode="HTML",
            )
            return
        clean = ",".join(raw_ports)
        await state.update_data(port_spec=clean, port_range=None)
        mode_label = f"✏️ Portlar: <code>{clean}</code>"

    await state.set_state(DeepScan.speed)
    await message.answer(
        f"✅ {mode_label}\n\n"
        "4️⃣  <b>Skan sürətini seçin:</b>\n\n"
        "  ⚡ <b>Sürətli (fast)</b> — 1s timeout · 100 thread · tez nəticə\n"
        "  🔬 <b>Dərin (deep)</b>   — 3s timeout · 30 thread · daha dəqiq",
        parse_mode="HTML",
        reply_markup=_kb_speed(),
    )


# ── Mərhələ 4 → cavab: sürət seçildi → skan başla ───────────
@router.message(DeepScan.speed)
async def dscan_got_speed(message: types.Message, state: FSMContext) -> None:
    choice = message.text.strip()

    if choice == "❌ Ləğv et":
        await _dscan_cancel(message, state)
        return

    if choice == "⚡ Sürətli (fast)":
        speed = "fast"
        speed_label = "⚡ Sürətli"
    elif choice == "🔬 Dərin (deep)":
        speed = "deep"
        speed_label = "🔬 Dərin"
    else:
        await message.answer(
            "⬇️ Zəhmət olmasa düymələrdən birini seçin.",
            reply_markup=_kb_speed(),
        )
        return

    data = await state.get_data()
    await state.clear()

    domain     = data["domain"]
    port_spec  = data.get("port_spec")
    port_range = data.get("port_range")

    # Özet mesajı
    if port_spec:
        ports_summary = f"✏️ Xüsusi: <code>{port_spec}</code>"
    elif port_range:
        ports_summary = f"📐 Aralıq: <code>{port_range}</code>"
    else:
        ports_summary = "🗂 Ümumi portlar (17)"

    wait_msg = await message.answer(
        "🔬 <b>Dərin Port Skanı Başladı</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 Hədəf:  <code>{domain}</code>\n"
        f"📋 Portlar: {ports_summary}\n"
        f"🏎 Sürət:  {speed_label}\n\n"
        "<i>⏳ Zəhmət olmasa gözləyin...</i>",
        parse_mode="HTML",
        reply_markup=_kb_remove(),
    )

    try:
        result = await _run_sync(
            _port.scan,
            domain,
            port_spec,
            port_range,
            speed,
            False,
        )
    except Exception as exc:
        logger.exception("deepportscan FSM xəta: %s", exc)
        await wait_msg.delete()
        await message.answer(
            f"❌ <b>Gözlənilməz xəta:</b>\n<code>{exc}</code>",
            parse_mode="HTML",
        )
        return

    await wait_msg.delete()

    if result.get("error"):
        await message.answer(
            f"❌ <b>Xəta:</b>\n<code>{result['error']}</code>",
            parse_mode="HTML",
        )
        return

    # ── Nəticələri format et ──────────────────────────────────
    open_ports    = result.get("open_ports", [])
    risk          = result.get("risk", "unknown")
    risk_icon     = RISK_ICONS.get(risk, "⚪")
    risk_analysis = result.get("risk_analysis", [])
    total_scanned = result.get("total_scanned", 0)

    # Port cədvəli
    if not open_ports:
        ports_text = "  🔒 <i>Açıq port tapılmadı</i>"
    else:
        ports_text = "\n".join(
            f"  {PORT_STATE_ICONS.get(p['state'], '⚪')} "
            f"<code>{str(p['port']):<6}</code> "
            f"<b>{p.get('service', 'Unknown')}</b>"
            + (f"\n    <i>↳ {p['banner'][:60]}</i>" if p.get("banner") else "")
            for p in open_ports
        )

    # Risk analizi
    if risk_analysis:
        risky   = [a for a in risk_analysis if a["is_risky"]]
        safe_pa = [a for a in risk_analysis if not a["is_risky"]]
        analysis_lines = []
        if risky:
            analysis_lines.append("⚠️ <b>Riskli portlar:</b>")
            for a in risky:
                analysis_lines.append(
                    f"  🔴 Port <code>{a['port']}</code> ({a['service']})\n"
                    f"    ├ <i>{a['risk_desc']}</i>\n"
                    f"    └ 💡 {a['recommendation']}"
                )
        if safe_pa:
            analysis_lines.append("\n📋 <b>Digər açıq portlar:</b>")
            for a in safe_pa:
                analysis_lines.append(
                    f"  🟡 Port <code>{a['port']}</code> ({a['service']})\n"
                    f"    └ <i>{a['risk_desc']}</i>"
                )
        analysis_text = "\n".join(analysis_lines)
    else:
        analysis_text = "  <i>Aşkar edilmiş portlar üçün risk profili yoxdur.</i>"

    text = _safe_truncate(
        "🔬 <b>Dərin Port Analizi — Nəticə</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🎯 Hədəf:       <code>{domain}</code>\n"
        f"📡 IP:          <code>{result.get('ip', '—')}</code>\n"
        f"📋 Port rejimi: {ports_summary}\n"
        f"🏎 Sürət:       {speed_label}\n"
        f"🔢 Skan edildi: <b>{total_scanned}</b> port\n"
        f"🟢 Açıq port:   <b>{len(open_ports)}</b>\n"
        f"{risk_icon} Risk:          <b>{risk.upper()}</b>\n\n"
        f"<b>Açıq portlar:</b>\n{ports_text}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━\n"
        f"{analysis_text}"
    )
    await message.answer(text, parse_mode="HTML")


# ── Ləğv etmə köməkçisi ───────────────────────────────────────
async def _dscan_cancel(message: types.Message, state: FSMContext) -> None:
    await state.clear()
    await message.answer(
        "❌ <b>Port skanı ləğv edildi.</b>",
        parse_mode="HTML",
        reply_markup=_kb_remove(),
    )


# ═════════════════════════════════════════════════════════════
# /scan  — 6-in-1 Tam Analiz (ScannerService.full_scan_async)
# DNS + SSL + Headers + Tech + Ports birlikdə
# ═════════════════════════════════════════════════════════════
@router.message(Command("scan"))
@with_wait_message(
    "🛡 <b>{target}</b> üzrə tam kibertəhlükəsizlik analizi aparılır...\n"
    "<i>(DNS · SSL · Headers · Tech · Ports — bu 30-60 saniyə çəkə bilər)</i>"
)
async def cmd_scan(message: types.Message, wait_msg: types.Message) -> None:
    args = _parse_args(message)
    if not args:
        await _usage_error(message, "/scan google.com")
        return

    domain = args[0]
    result = await _scanner.full_scan_async(domain)

    # ── DNS ──────────────────────────────────────────────────
    dns_data = result.get("dns", {}).get("dns", {})
    a_records = _fmt_list(dns_data.get("A", []), limit=3)

    # ── SSL ──────────────────────────────────────────────────
    ssl       = result.get("ssl", {})
    ssl_valid = ssl.get("valid", False)
    ssl_icon  = "✅" if ssl_valid else "❌"
    ssl_stat  = ssl.get("ssl_status", "unknown").upper()
    ssl_exp   = ssl.get("expires") or "—"
    ssl_tls   = ssl.get("tls_version") or "—"
    issuer    = _ssl_issuer_str(ssl.get("issuer"))

    # Bitmə xəbərdarlığı
    ssl_warn = ""
    if ssl_valid and ssl_exp != "—":
        from datetime import datetime
        try:
            exp_dt    = datetime.strptime(ssl_exp, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_dt - datetime.utcnow()).days
            if days_left < 0:
                ssl_warn = " ⛔ <b>BITMƏ MÜDDƏTİ KEÇİB!</b>"
            elif days_left <= 30:
                ssl_warn = f" ⚠️ <b>{days_left} gün qalıb!</b>"
        except Exception:
            pass

    # ── Headers ──────────────────────────────────────────────
    hdr       = result.get("headers", {})
    hdr_risk  = hdr.get("risk", "unknown")
    hdr_icon  = RISK_ICONS.get(hdr_risk, "⚪")
    present   = hdr.get("present", {})
    missing   = hdr.get("missing", [])
    hdr_score = f"{len(present)}/{len(present) + len(missing)}"

    # ── Tech ─────────────────────────────────────────────────
    tech      = result.get("technology", {})
    server    = tech.get("server") or "—"
    framework = tech.get("framework") or "—"
    cms       = tech.get("cms") or "—"
    cdn       = tech.get("cdn") or "—"

    # ── Ports ────────────────────────────────────────────────
    ports_data  = result.get("ports", {})
    open_ports  = ports_data.get("open_ports", [])
    port_risk   = ports_data.get("risk", "unknown")
    port_icon   = RISK_ICONS.get(port_risk, "⚪")
    port_ip     = ports_data.get("ip", "—")

    if open_ports:
        port_lines = "  " + ",  ".join(
            f"<code>{p['port']}</code>({p.get('service','?')})"
            for p in open_ports[:10]
        )
        if len(open_ports) > 10:
            port_lines += f"\n  +{len(open_ports)-10} daha..."
    else:
        port_lines = "  🔒 <i>Açıq port tapılmadı</i>"

    await wait_msg.delete()
    text = _safe_truncate(
        "🛡 <b>CyberGuard — Tam Analiz Hesabatı</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 Domain: <code>{domain}</code>  |  📡 IP: <code>{port_ip}</code>\n\n"

        "🗂 <b>DNS</b>\n"
        f"  A qeydləri: <code>{a_records}</code>\n\n"

        "🔒 <b>SSL Sertifikat</b>\n"
        f"  {ssl_icon} Status:  <b>{ssl_stat}</b>{ssl_warn}\n"
        f"  🏷 Emitent: <code>{issuer}</code>\n"
        f"  📅 Bitmə:   <code>{ssl_exp}</code>\n"
        f"  🔑 TLS:     <code>{ssl_tls}</code>\n\n"

        "🛡 <b>HTTP Başlıqları</b>\n"
        f"  {hdr_icon} Risk: <b>{hdr_risk.upper()}</b>  |  Xal: <b>{hdr_score}</b>\n"
        + (f"  ❌ Çatışmayan: <code>{', '.join(missing[:3])}</code>\n" if missing else "  ✅ Bütün başlıqlar mövcuddur\n")
        + "\n"

        "🧠 <b>Texnologiya</b>\n"
        f"  🖥 Server:    <code>{server}</code>\n"
        f"  ⚙️ Framework: <code>{framework}</code>\n"
        f"  📝 CMS:       <code>{cms}</code>\n"
        f"  ☁️ CDN:       <code>{cdn}</code>\n\n"

        "⚡ <b>Port Skanı</b>\n"
        f"  {port_icon} Risk: <b>{port_risk.upper()}</b>  |  Açıq: <b>{len(open_ports)}</b>\n"
        f"{port_lines}\n\n"
        "━━━━━━━━━━━━━━━━━━━━━\n"
        "<i>Ətraflı analiz üçün: /ssl /headers /tech /deepportscan /subdomains</i>"
    )
    await message.answer(text, parse_mode="HTML")


# ═════════════════════════════════════════════════════════════
# Naməlum əmrlər üçün fallback
# ═════════════════════════════════════════════════════════════
@router.message(F.text.startswith("/"))
async def cmd_unknown(message: types.Message) -> None:
    await message.answer(
        "❓ Naməlum əmr.\n"
        "Mövcud əmrlərin siyahısı üçün /help yazın.",
        parse_mode="HTML",
    )
