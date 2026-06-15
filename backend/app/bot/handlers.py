from aiogram import Router, types
from aiogram.filters import Command

# sys.path backend/ kökünə işarə etməlidir ki, bu import işləsin
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from backend.services.scanner_service import ScannerService
from backend.app.services.user_service import UserService

router = Router()

scanner = ScannerService()
user_service = UserService()


# -------------------------
# /start
# -------------------------
@router.message(Command("start"))
async def start(message: types.Message):
    user = await user_service.get_or_create_user(
        telegram_id=str(message.from_user.id),
        username=message.from_user.username
    )

    await message.answer(
        f"🛡 <b>CyberGuard-a xoş gəldiniz!</b>\n\n"
        f"Hər hansı bir domen haqqında təhlükəsizlik analizi əldə etmək üçün:\n"
        f"<code>/scan domain.com</code>\n\n"
        f"👤 User ID: <code>{user.id}</code>",
        parse_mode="HTML"
    )


# -------------------------
# /scan domain.com
# -------------------------
@router.message(Command("scan"))
async def scan(message: types.Message):
    args = message.text.split()

    if len(args) < 2:
        await message.answer("❌ İstifadə: <code>/scan domain.com</code>", parse_mode="HTML")
        return

    domain = args[1].strip()

    # Domain formatını yoxlayırıq
    if not domain or "." not in domain:
        await message.answer(
            "❌ Yanlış domen formatı. Nümunə: <code>/scan google.com</code>",
            parse_mode="HTML"
        )
        return

    wait_msg = await message.answer(
        f"🔍 <b>{domain}</b> skanlanır, zəhmət olmasa gözləyin...",
        parse_mode="HTML"
    )

    try:
        # async wrapper istifadə edirik — event loop bloklanmır
        result = await scanner.full_scan_async(domain=domain)
    except Exception as e:
        await wait_msg.delete()
        await message.answer(
            f"❌ Scan zamanı xəta baş verdi:\n<code>{str(e)}</code>",
            parse_mode="HTML"
        )
        return

    await wait_msg.delete()

    dns     = result.get("dns", {}).get("dns", {})
    ssl     = result.get("ssl", {})
    tech    = result.get("technology", {})
    headers = result.get("headers", {})
    ports   = result.get("ports", {})

    # --- SSL bloku ---
    ssl_icon = "✅" if ssl.get("valid") else "❌"
    ssl_block = (
        f"{ssl_icon} <b>SSL Sertifikat</b>\n"
        f"  Status: <code>{ssl.get('ssl_status', 'unknown')}</code>\n"
        f"  TLS: <code>{ssl.get('tls_version', 'N/A')}</code>\n"
        f"  Issuer: <code>{ssl.get('issuer', 'N/A')}</code>\n"
        f"  Bitmə tarixi: <code>{ssl.get('expires', 'N/A')}</code>"
    )

    # --- Tech bloku ---
    tech_block = (
        f"🧠 <b>Texnologiya</b>\n"
        f"  Server: <code>{tech.get('server') or 'Naməlum'}</code>\n"
        f"  Framework: <code>{tech.get('framework') or 'Naməlum'}</code>\n"
        f"  CMS: <code>{tech.get('cms') or 'Naməlum'}</code>\n"
        f"  CDN: <code>{tech.get('cdn') or 'Naməlum'}</code>"
    )

    # --- DNS bloku ---
    def fmt_list(lst):
        return ", ".join(lst) if lst else "—"

    dns_block = (
        f"🌍 <b>DNS Qeydləri</b>\n"
        f"  A: <code>{fmt_list(dns.get('A'))}</code>\n"
        f"  AAAA: <code>{fmt_list(dns.get('AAAA'))}</code>\n"
        f"  MX: <code>{fmt_list(dns.get('MX'))}</code>\n"
        f"  NS: <code>{fmt_list(dns.get('NS'))}</code>\n"
        f"  TXT: <code>{fmt_list(dns.get('TXT'))}</code>\n"
        f"  CNAME: <code>{fmt_list(dns.get('CNAME'))}</code>"
    )

    # --- Header bloku ---
    risk = headers.get("risk", "unknown")
    risk_icon = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(risk, "⚪")

    missing = headers.get("missing", [])
    present = headers.get("present", {})

    missing_text = "\n".join(f"    ❌ {h}" for h in missing) if missing else "    ✅ Hamısı mövcuddur"
    present_text = "\n".join(f"    ✅ {h}" for h in present.keys()) if present else "    —"

    header_block = (
        f"🔒 <b>HTTP Təhlükəsizlik Başlıqları</b>\n"
        f"  Mövcud:\n{present_text}\n"
        f"  Çatışmayan:\n{missing_text}"
    )

    # --- Port bloku ---
    open_ports = ports.get("open_ports", [])
    port_ip    = ports.get("ip") or "N/A"
    port_risk  = ports.get("risk", "unknown")
    port_error = ports.get("error")

    HIGH_RISK_PORTS = {23, 445, 3306, 3389, 5432, 6379, 27017}

    if port_error:
        ports_text = f"    ⚠️ <i>{port_error}</i>"
    elif open_ports:
        port_lines = []
        for p in open_ports:
            icon = "⚠️" if p["port"] in HIGH_RISK_PORTS else "🟢"
            banner_text = f" — <i>{p['banner'][:40]}</i>" if p.get("banner") else ""
            port_lines.append(
                f"    {icon} <code>{p['port']}</code> {p.get('service', 'Unknown')}{banner_text}"
            )
        ports_text = "\n".join(port_lines)
    else:
        ports_text = "    ✅ Açıq port tapılmadı"

    port_risk_icon = {"low": "🟢", "medium": "🟡", "high": "🔴", "minimal": "🟢"}.get(port_risk, "⚪")

    port_block = (
        f"🔌 <b>Port Skanı</b>  (IP: <code>{port_ip}</code>)\n"
        f"{ports_text}\n"
        f"  {port_risk_icon} Port riski: <b>{port_risk.upper()}</b>"
    )

    # --- Ümumi risk hesablaması ---
    risks = [headers.get("risk", "low"), port_risk]
    if "high" in risks:
        overall_risk = "high"
        overall_icon = "🔴"
    elif "medium" in risks:
        overall_risk = "medium"
        overall_icon = "🟡"
    else:
        overall_risk = "low"
        overall_icon = "🟢"

    risk_block = f"{overall_icon} <b>Ümumi Risk Səviyyəsi: {overall_risk.upper()}</b>"

    # --- Final mesaj ---
    response_text = (
        f"🛡 <b>CyberGuard Scan Nəticəsi</b>\n"
        f"🌐 Hədəf: <code>{domain}</code>\n"
        f"{'─' * 30}\n\n"
        f"{ssl_block}\n\n"
        f"{tech_block}\n\n"
        f"{dns_block}\n\n"
        f"{header_block}\n\n"
        f"{port_block}\n\n"
        f"{'─' * 30}\n"
        f"{risk_block}"
    )

    await message.answer(response_text, parse_mode="HTML")
