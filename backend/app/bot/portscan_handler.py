"""
/portscan komandası üçün interaktiv handler.

İstifadə:
  /portscan domain.com            → default skan (ümumi portlar, fast, yalnız açıqlar)
  /portscan domain.com 1-1000     → port aralığı
  /portscan domain.com 80,443,22  → xüsusi portlar

İnteraktiv seçimlər (inline keyboard):
  • Port range: Common | 1-1000 | 1-65535 | Xüsusi
  • Sürət: Sürətli (fast) | Dərin (deep)
  • Göstər: Yalnız açıq | Hamısı
"""

import asyncio
import re
from aiogram import Router, types, F
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

# sys.path düzəltmək üçün (bot.py ilə eyni pattern)
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from backend.scanners.port_scanner_advanced import AdvancedPortScanner

router = Router()
scanner = AdvancedPortScanner()

# ──────────────────────────────────────────────
# Callback data formatları:
#   ps_range:{domain}:{range_key}
#   ps_speed:{domain}:{range_key}:{speed}
#   ps_show:{domain}:{range_key}:{speed}:{show}
#   ps_custom:{domain}            → gözlə user input
#   ps_go:{domain}:{range_key}:{speed}:{show}
# ──────────────────────────────────────────────

HIGH_RISK = {23, 445, 3306, 3389, 5432, 6379, 27017}

RANGE_LABELS = {
    "common":  "📋 Ümumi portlar",
    "1-1000":  "🔢 1-1000",
    "1-65535": "🌐 Tam skan (1-65535)",
}


def _main_keyboard(domain: str) -> InlineKeyboardMarkup:
    """Başlanğıc interaktiv menyu."""
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="📋 Ümumi", callback_data=f"ps_range:{domain}:common"),
            InlineKeyboardButton(text="🔢 1-1000", callback_data=f"ps_range:{domain}:1-1000"),
        ],
        [
            InlineKeyboardButton(text="🌐 Tam (1-65535)", callback_data=f"ps_range:{domain}:1-65535"),
            InlineKeyboardButton(text="✏️ Xüsusi portlar", callback_data=f"ps_custom:{domain}"),
        ],
    ])


def _speed_keyboard(domain: str, range_key: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="⚡ Sürətli", callback_data=f"ps_speed:{domain}:{range_key}:fast"),
            InlineKeyboardButton(text="🔬 Dərin skan", callback_data=f"ps_speed:{domain}:{range_key}:deep"),
        ],
        [InlineKeyboardButton(text="◀️ Geri", callback_data=f"ps_back:{domain}")],
    ])


def _show_keyboard(domain: str, range_key: str, speed: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="🟢 Yalnız açıq portlar", callback_data=f"ps_show:{domain}:{range_key}:{speed}:open"),
            InlineKeyboardButton(text="📊 Hamısını göstər", callback_data=f"ps_show:{domain}:{range_key}:{speed}:all"),
        ],
        [InlineKeyboardButton(text="◀️ Geri", callback_data=f"ps_range:{domain}:{range_key}")],
    ])


def _confirm_keyboard(domain: str, range_key: str, speed: str, show: str) -> InlineKeyboardMarkup:
    speed_label = "⚡ Sürətli" if speed == "fast" else "🔬 Dərin"
    show_label = "🟢 Yalnız açıq" if show == "open" else "📊 Hamısı"
    range_label = RANGE_LABELS.get(range_key, f"🔌 {range_key}")
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(
            text=f"🚀 Başlat: {range_label} | {speed_label} | {show_label}",
            callback_data=f"ps_go:{domain}:{range_key}:{speed}:{show}"
        )],
        [InlineKeyboardButton(text="◀️ Geri", callback_data=f"ps_speed:{domain}:{range_key}:{speed}")],
    ])


# ──────────────────────────────────────────────
# /portscan handler
# ──────────────────────────────────────────────

@router.message(Command("portscan"))
async def portscan_cmd(message: types.Message):
    parts = message.text.split(maxsplit=2)

    if len(parts) < 2:
        await message.answer(
            "❌ İstifadə:\n"
            "<code>/portscan domain.com</code>\n"
            "<code>/portscan domain.com 1-1000</code>\n"
            "<code>/portscan domain.com 80,443,8080</code>",
            parse_mode="HTML"
        )
        return

    domain = parts[1].strip().lower()
    if not domain or "." not in domain:
        await message.answer("❌ Yanlış domen. Nümunə: <code>/portscan google.com</code>", parse_mode="HTML")
        return

    # İkinci arqument varsa — birbaşa skan başlat
    if len(parts) == 3:
        port_arg = parts[2].strip()
        await message.answer(
            f"🔌 <b>Port Skanı</b>\n"
            f"🌐 Hədəf: <code>{domain}</code>\n"
            f"🔢 Portlar: <code>{port_arg}</code>\n"
            f"⏳ Skan başlayır...",
            parse_mode="HTML"
        )
        await _run_scan(message, domain, port_arg, speed="fast", show_all=False)
        return

    # Yoxsa interaktiv menyu aç
    await message.answer(
        f"🔌 <b>Port Skanı Konfiqurasiyası</b>\n"
        f"🌐 Hədəf: <code>{domain}</code>\n\n"
        f"Port aralığını seçin:",
        parse_mode="HTML",
        reply_markup=_main_keyboard(domain)
    )


# ──────────────────────────────────────────────
# Callback: Geri → ana menyu
# ──────────────────────────────────────────────

@router.callback_query(F.data.startswith("ps_back:"))
async def cb_back(call: types.CallbackQuery):
    domain = call.data.split(":", 1)[1]
    await call.message.edit_text(
        f"🔌 <b>Port Skanı Konfiqurasiyası</b>\n"
        f"🌐 Hədəf: <code>{domain}</code>\n\n"
        f"Port aralığını seçin:",
        parse_mode="HTML",
        reply_markup=_main_keyboard(domain)
    )
    await call.answer()


# ──────────────────────────────────────────────
# Callback: Xüsusi portlar — gözlə
# ──────────────────────────────────────────────

@router.callback_query(F.data.startswith("ps_custom:"))
async def cb_custom(call: types.CallbackQuery):
    domain = call.data.split(":", 1)[1]
    await call.message.edit_text(
        f"✏️ <b>Xüsusi portlar</b>\n"
        f"🌐 Hədəf: <code>{domain}</code>\n\n"
        f"Portları göndərin (vergüllə ayrılmış və ya aralıq):\n"
        f"Nümunə: <code>80,443,8080</code> və ya <code>1-1000</code>",
        parse_mode="HTML"
    )
    # Pending state saxlayırıq — sadə yanaşma: sonrakı mesajda @domain-ə baxarıq
    # Real state management üçün FSM istifadə olunmalıdır
    # Burada pending dict istifadə edirik
    _pending_custom[call.from_user.id] = domain
    await call.answer()


# pending custom input state
_pending_custom: dict[int, str] = {}


@router.message(F.text)
async def handle_custom_ports(message: types.Message):
    user_id = message.from_user.id
    if user_id not in _pending_custom:
        return  # Bu handler yalnız pending state-də işləyir

    domain = _pending_custom.pop(user_id)
    port_arg = message.text.strip()

    # Yoxlama: yalnız rəqəmlər, vergüllər, tire
    if not re.match(r'^[\d,\-\s]+$', port_arg):
        await message.answer(
            "❌ Yanlış format. Yalnız rəqəm, vergül və tire istifadə edin.\n"
            "Nümunə: <code>80,443,8080</code> və ya <code>1-1000</code>",
            parse_mode="HTML"
        )
        return

    range_key = port_arg.replace(" ", "")
    await message.answer(
        f"🔌 <b>Sürət seçin</b>\n"
        f"🌐 Hədəf: <code>{domain}</code>\n"
        f"🔢 Portlar: <code>{range_key}</code>",
        parse_mode="HTML",
        reply_markup=_speed_keyboard(domain, range_key)
    )


# ──────────────────────────────────────────────
# Callback: Range seçimi
# ──────────────────────────────────────────────

@router.callback_query(F.data.startswith("ps_range:"))
async def cb_range(call: types.CallbackQuery):
    _, domain, range_key = call.data.split(":", 2)
    range_label = RANGE_LABELS.get(range_key, range_key)
    await call.message.edit_text(
        f"🔌 <b>Sürət seçin</b>\n"
        f"🌐 Hədəf: <code>{domain}</code>\n"
        f"📋 Portlar: {range_label}",
        parse_mode="HTML",
        reply_markup=_speed_keyboard(domain, range_key)
    )
    await call.answer()


# ──────────────────────────────────────────────
# Callback: Sürət seçimi
# ──────────────────────────────────────────────

@router.callback_query(F.data.startswith("ps_speed:"))
async def cb_speed(call: types.CallbackQuery):
    parts = call.data.split(":", 3)
    domain, range_key, speed = parts[1], parts[2], parts[3]
    speed_label = "⚡ Sürətli" if speed == "fast" else "🔬 Dərin"
    range_label = RANGE_LABELS.get(range_key, range_key)
    await call.message.edit_text(
        f"🔌 <b>Göstərmə rejimi</b>\n"
        f"🌐 Hədəf: <code>{domain}</code>\n"
        f"📋 Portlar: {range_label}\n"
        f"⚡ Sürət: {speed_label}",
        parse_mode="HTML",
        reply_markup=_show_keyboard(domain, range_key, speed)
    )
    await call.answer()


# ──────────────────────────────────────────────
# Callback: Göstərmə seçimi → Təsdiq
# ──────────────────────────────────────────────

@router.callback_query(F.data.startswith("ps_show:"))
async def cb_show(call: types.CallbackQuery):
    parts = call.data.split(":", 4)
    domain, range_key, speed, show = parts[1], parts[2], parts[3], parts[4]
    range_label = RANGE_LABELS.get(range_key, f"🔌 {range_key}")
    speed_label = "⚡ Sürətli" if speed == "fast" else "🔬 Dərin"
    show_label = "🟢 Yalnız açıq" if show == "open" else "📊 Hamısı"
    await call.message.edit_text(
        f"🔌 <b>Skan parametrləri hazırdır</b>\n"
        f"🌐 Hədəf: <code>{domain}</code>\n"
        f"📋 Portlar: {range_label}\n"
        f"⚡ Sürət: {speed_label}\n"
        f"👁 Göstər: {show_label}\n\n"
        f"Skanı başlatmaq üçün düyməyə basın:",
        parse_mode="HTML",
        reply_markup=_confirm_keyboard(domain, range_key, speed, show)
    )
    await call.answer()


# ──────────────────────────────────────────────
# Callback: Skanı başlat
# ──────────────────────────────────────────────

@router.callback_query(F.data.startswith("ps_go:"))
async def cb_go(call: types.CallbackQuery):
    parts = call.data.split(":", 4)
    domain, range_key, speed, show = parts[1], parts[2], parts[3], parts[4]
    show_all = (show == "all")

    range_label = RANGE_LABELS.get(range_key, f"🔌 {range_key}")
    speed_label = "⚡ Sürətli" if speed == "fast" else "🔬 Dərin"

    await call.message.edit_text(
        f"⏳ <b>Skanlanır...</b>\n"
        f"🌐 Hədəf: <code>{domain}</code>\n"
        f"📋 Portlar: {range_label}\n"
        f"⚡ Sürət: {speed_label}\n\n"
        f"<i>Bu proses bir neçə dəqiqə çəkə bilər...</i>",
        parse_mode="HTML"
    )
    await call.answer("Skan başladı ⏳")

    # Range key → port arg
    if range_key == "common":
        port_arg = None
        port_range_arg = None
    elif "-" in range_key and range_key.replace("-", "").replace("0", "").replace("1", "").replace("6", "").replace("5", "").replace("3", "").replace("9", "").isdigit() or "-" in range_key:
        port_arg = None
        port_range_arg = range_key
    else:
        port_arg = range_key
        port_range_arg = None

    await _run_scan(
        call.message, domain,
        port_arg=port_arg,
        port_range=port_range_arg,
        speed=speed,
        show_all=show_all,
        edit=True
    )


# ──────────────────────────────────────────────
# Skan işlətmə funksiyası
# ──────────────────────────────────────────────

async def _run_scan(
    message: types.Message,
    domain: str,
    port_arg=None,      # "80,443,8080" və ya None
    port_range=None,    # "1-1000" və ya None
    speed="fast",
    show_all=False,
    edit=False
):
    loop = asyncio.get_event_loop()

    def _do_scan():
        return scanner.scan(
            domain=domain,
            port_spec=port_arg,
            port_range=port_range,
            speed=speed,
            show_all=show_all
        )

    try:
        result = await loop.run_in_executor(None, _do_scan)
    except Exception as e:
        text = f"❌ Skan zamanı xəta:\n<code>{e}</code>"
        if edit:
            await message.edit_text(text, parse_mode="HTML")
        else:
            await message.answer(text, parse_mode="HTML")
        return

    text = _format_result(domain, result, show_all)

    if edit:
        # Telegram mesaj limiti 4096 simvol
        if len(text) > 4096:
            await message.edit_text(text[:4090] + "...", parse_mode="HTML")
        else:
            await message.edit_text(text, parse_mode="HTML")
    else:
        if len(text) > 4096:
            await message.answer(text[:4090] + "...", parse_mode="HTML")
        else:
            await message.answer(text, parse_mode="HTML")


def _format_result(domain: str, result: dict, show_all: bool) -> str:
    if result.get("error"):
        return f"❌ <b>Xəta:</b> <code>{result['error']}</code>"

    ip = result.get("ip", "N/A")
    total = result.get("total_scanned", 0)
    open_ports = result.get("open_ports", [])
    risk = result.get("risk", "unknown")
    risk_analysis = result.get("risk_analysis", [])
    scan_mode = result.get("scan_mode", "")

    risk_icon = {"low": "🟢", "medium": "🟡", "high": "🔴", "minimal": "🟢"}.get(risk, "⚪")

    # ── Port siyahısı ──
    if open_ports:
        port_lines = []
        for p in open_ports:
            port_num = p["port"]
            icon = "⚠️" if port_num in HIGH_RISK else "🟢"
            banner_part = f" — <i>{p['banner'][:35]}</i>" if p.get("banner") else ""
            port_lines.append(
                f"  {icon} <code>{port_num:5d}</code>  {p.get('service', 'Unknown')}{banner_part}"
            )
        ports_text = "\n".join(port_lines)
    else:
        ports_text = "  ✅ Açıq port tapılmadı"

    # ── Bütün portlar (show_all) ──
    all_ports_section = ""
    if show_all and result.get("ports"):
        closed = [p for p in result["ports"] if p["state"] == "closed"]
        filtered = [p for p in result["ports"] if p["state"] == "filtered"]
        all_ports_section = (
            f"\n📊 <b>Skan statistikası</b>\n"
            f"  🟢 Açıq: {len(open_ports)}\n"
            f"  ⭕ Bağlı: {len(closed)}\n"
            f"  🔘 Filtered: {len(filtered)}\n"
        )

    # ── Risk analizi ──
    risk_section = ""
    if risk_analysis:
        risk_lines = []
        for ra in risk_analysis:
            icon = "🔴" if ra["is_risky"] else "🟡"
            risk_lines.append(
                f"  {icon} <b>Port {ra['port']} ({ra['service']})</b>\n"
                f"      ⚠️ {ra['risk_desc']}\n"
                f"      💡 {ra['recommendation']}"
            )
        risk_section = "\n\n🔍 <b>Risk Analizi</b>\n" + "\n\n".join(risk_lines)

    return (
        f"🔌 <b>Port Skanı Nəticəsi</b>\n"
        f"🌐 Hədəf: <code>{domain}</code>\n"
        f"📡 IP: <code>{ip}</code>\n"
        f"🔎 Yoxlanan port: <code>{total}</code>  |  {scan_mode}\n"
        f"{'─' * 30}\n\n"
        f"<b>Açıq portlar:</b>\n{ports_text}"
        f"{all_ports_section}"
        f"{risk_section}\n\n"
        f"{'─' * 30}\n"
        f"{risk_icon} <b>Port riski: {risk.upper()}</b>"
    )
