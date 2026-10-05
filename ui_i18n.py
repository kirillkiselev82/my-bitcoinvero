# ui_i18n.py
from __future__ import annotations

from typing import Optional, Dict

import panel as pn

# ---------------- i18n ----------------
LANGS = ["RU", "EN"]

I18N: Dict[str, Dict[str, str]] = {
    "data": {"RU": "Данные", "EN": "Data"},
    "range": {"RU": "Диапазон (график/расчёт)", "EN": "Range (chart/backtest)"},
    "indicators": {"RU": "Индикаторы", "EN": "Indicators"},
    "onchain_tools": {"RU": "On-chain (master)", "EN": "On-chain (master)"},
    "onchain_window_days": {"RU": "Окно инкремента (дней)", "EN": "Increment window (days)"},
    "onchain_update": {"RU": "Обновить индикаторы (тяжёлая)", "EN": "Update indicators (heavy)"},
    "onchain_reload": {"RU": "Перечитать индикаторы (быстро)", "EN": "Reload indicators (fast)"},
    "onchain_status": {"RU": "Статус on-chain", "EN": "On-chain status"},

    "ind_select": {"RU": "Индикаторы", "EN": "Indicators"},
    "ind_max_points": {"RU": "Макс. точек (индикаторы)", "EN": "Max points (indicators)"},
    "ind_clear": {"RU": "Очистить индикаторы", "EN": "Clear indicators"},
    "display": {"RU": "Отображение", "EN": "Display"},
    "strategy": {"RU": "Стратегия", "EN": "Strategy"},
    "mode": {"RU": "Режим торговли / Параметры ZZ2", "EN": "Trading mode / ZZ2 parameters"},
    "risk": {"RU": "Капитал / Комиссия / Проскальзывание / SL / TP", "EN": "Capital / Fee / Slippage / SL / TP"},
    "pine_inputs": {"RU": "Pine inputs", "EN": "Pine inputs"},
    "layers": {"RU": "Отображение слоёв", "EN": "Layers visibility"},
    "chart_layers": {"RU": "График — слои", "EN": "Chart layers"},
    "metrics_trades": {"RU": "Метрики / сделки", "EN": "Metrics / trades"},
    "trades": {"RU": "Журнал сделок", "EN": "Trades"},
    "equity_curve": {"RU": "Equity curve (график доходности)", "EN": "Equity curve"},
    "equity_table": {"RU": "Equity (таблица)", "EN": "Equity (table)"},
    "run": {"RU": "Запустить бэктест", "EN": "Run backtest"},
    "redraw": {"RU": "Перерисовать график", "EN": "Redraw chart"},
    "done": {"RU": "Готово.", "EN": "Done."},
    "src": {"RU": "Источник данных", "EN": "Data source"},
    "disk": {"RU": "Файл на диске", "EN": "File on disk"},
    "upload": {"RU": "Upload CSV", "EN": "Upload CSV"},
    "data_dir": {"RU": "Папка data", "EN": "Data folder"},
    "csv": {"RU": "CSV файл", "EN": "CSV file"},
    "symbol": {"RU": "Symbol", "EN": "Symbol"},
    "tf": {"RU": "Timeframe", "EN": "Timeframe"},
    "date_from": {"RU": "С даты (YYYY-MM-DD)", "EN": "From (YYYY-MM-DD)"},
    "date_to": {"RU": "По дату (YYYY-MM-DD)", "EN": "To (YYYY-MM-DD)"},
    "warmup": {"RU": "Warmup bars", "EN": "Warmup bars"},
    "chart_mode": {"RU": "Вид графика", "EN": "Chart mode"},
    "max_points": {"RU": "Макс. точек (Line)", "EN": "Max points (Line)"},
    "hm_tb": {"RU": "Heatmap time bins", "EN": "Heatmap time bins"},
    "hm_pb": {"RU": "Heatmap price bins", "EN": "Heatmap price bins"},
    "strat_lang": {"RU": "Формат стратегии", "EN": "Strategy format"},
    "strat_dir": {"RU": "Папка со стратегиями", "EN": "Strategies folder"},
    "py_strat": {"RU": "Python стратегия", "EN": "Python strategy"},
    "yaml_strat": {"RU": "YAML стратегия", "EN": "YAML strategy"},
    "allow_long": {"RU": "Разрешить вход Long", "EN": "Allow Long entries"},
    "allow_short": {"RU": "Разрешить вход Short", "EN": "Allow Short entries"},
    "reverse": {"RU": "Reverse logic", "EN": "Reverse logic"},
    "length": {"RU": "Length", "EN": "Length"},
    "extreme": {"RU": "Extreme", "EN": "Extreme"},
    "corr": {"RU": "Corr (%)", "EN": "Corr (%)"},
    "show_trades": {"RU": "Показывать сделки", "EN": "Show trades"},
    "show_entries": {"RU": "Показывать входы", "EN": "Show entries"},
    "show_exits": {"RU": "Показывать выходы", "EN": "Show exits"},
    "price_log": {"RU": "Лог шкала цены", "EN": "Log price scale"},
    "show_uplevel": {"RU": "Уровень LONG (uplevel)", "EN": "LONG level (uplevel)"},
    "show_dnlevel": {"RU": "Уровень SHORT (dnlevel)", "EN": "SHORT level (dnlevel)"},
    "show_pop_pivots": {"RU": "PoP: pivots (hprice/lprice)", "EN": "PoP: pivots (hprice/lprice)"},
    "show_pop_levels": {"RU": "PoP: levels (pph/ppl)", "EN": "PoP: levels (pph/ppl)"},

    "pop_left_bars": {"RU": "PoP: PP Left Bars", "EN": "PoP: PP Left Bars"},
    "pop_right_bars": {"RU": "PoP: PP Right Bars", "EN": "PoP: PP Right Bars"},
    "pop_atr_length": {"RU": "PoP: ATR Length", "EN": "PoP: ATR Length"},
    "pop_atr_mult": {"RU": "PoP: ATR Mult", "EN": "PoP: ATR Mult"},
    "pop_min_tick": {"RU": "PoP: min_tick", "EN": "PoP: min_tick"},

    "fishnet_filter": {"RU": "Fishnet filter", "EN": "Fishnet filter"},
    "fishnet_tf": {"RU": "Fishnet TF", "EN": "Fishnet TF"},
    "fishnet_start_len": {"RU": "Fishnet start len", "EN": "Fishnet start len"},
    "fishnet_step": {"RU": "Fishnet step", "EN": "Fishnet step"},
    "fishnet_count": {"RU": "Fishnet count", "EN": "Fishnet count"},

    # PoP execution model (bot-like)
    "pop_real_trade": {"RU": "Real pop_reversal trade", "EN": "Real pop_reversal trade"},
    "exec_model": {"RU": "Execution model", "EN": "Execution model"},
    "exec_det": {"RU": "Bot-like (deterministic)", "EN": "Bot-like (deterministic)"},
    "exec_cons": {"RU": "Bot-like (conservative)", "EN": "Bot-like (conservative)"},

    "show_break": {"RU": "Break level (линии)", "EN": "Break level (lines)"},
    "initial_cap": {"RU": "Первоначальный капитал (USD)", "EN": "Initial Capital (USD)"},
    "no_reinvest": {"RU": "Не реинвестировать прибыль", "EN": "Do not reinvest profits"},
    # note texts
    "warmup_help": {
        "RU": "Добавляет бары до `С даты` для прогрева индикаторов. На диапазон отображения не влияет.",
        "EN": "Adds bars before `From` to warm up indicators. Does not change the visible range.",
    },
    "hm_tb_help": {"RU": "Число корзин по времени. Больше = детальнее, но медленнее.", "EN": "Number of time bins. More = more detail, slower."},
    "hm_pb_help": {"RU": "Число корзин по цене. Больше = детальнее, но медленнее.", "EN": "Number of price bins. More = more detail, slower."},
}

# Keyed metric comments (no header line)
HELP_METRICS: Dict[str, Dict[str, str]] = {
    "RU": {
        "Final Equity": "итоговый капитал в долях от старта (2.00 = x2).",
        "Total Return": "доходность к старту (1.00 = +100%).",
        "Max Drawdown": "максимальная просадка от пика (−0.67 = −67%).",
        "Sharpe (rough)": "грубый Sharpe (без risk-free), больше = стабильнее.",
        "Trades": "число закрытых сделок.",
        "Win Rate": "доля прибыльных сделок (0.40 = 40%).",
        "Fee": "комиссия в долях (0.001 = 0.1%).",
        "Slippage": "проскальзывание в долях.",
        "intrabar_priority": "если на одной свече могли сработать и SL и TP: что считать первым (sl, tp, worst, best).",
        "Initial Capital (USD)": "стартовый капитал (по умолчанию 1000).",
        "Final Balance (USD)": "итоговый баланс = Initial Capital × Final Equity.",
    },
    "EN": {
        "Final Equity": "ending equity as a multiple of the start (2.00 = x2).",
        "Total Return": "return vs start (1.00 = +100%).",
        "Max Drawdown": "maximum peak-to-trough drawdown (−0.67 = −67%).",
        "Sharpe (rough)": "rough Sharpe (no risk-free), higher = smoother.",
        "Trades": "number of closed trades.",
        "Win Rate": "fraction of profitable trades (0.40 = 0.40).",
        "Fee": "fee as a fraction (0.001 = 0.1%).",
        "Slippage": "slippage as a fraction.",
        "intrabar_priority": "if SL and TP are both reachable within the same candle: which one is assumed first (sl, tp, worst, best).",
        "Initial Capital (USD)": "starting balance (default 1000).",
        "Final Balance (USD)": "ending balance = Initial Capital × Final Equity.",
    },
}

HELP_FIELDS = {
    "initial_cap": {
        "RU": "Стартовый капитал для расчёта итогового баланса (Final Balance). По умолчанию: 1000 USD.",
        "EN": "Starting capital used to compute Final Balance. Default: 1000 USD.",
    },
    "no_reinvest": {
        "RU": (
            "Если включено — прибыль/убыток НЕ реинвестируется: каждая сделка считается так,"
            " как будто размер позиции всегда равен первоначальному капиталу."
        ),
        "EN": (
            "If enabled, profits/losses are NOT compounded: each trade is sized from the initial capital."
        ),
    },
    "fee_pct": {
        "RU": "Комиссия в долях. Пример: 0.001 = 0.1%. Применяется к стоимости сделки.",
        "EN": "Fee as a fraction. Example: 0.001 = 0.1%. Applied to trade value.",
    },
    "slippage_bps": {
        "RU": "Проскальзывание в bps. 1 bps = 0.01%. Пример: 10 bps = 0.1%.",
        "EN": "Slippage in bps. 1 bps = 0.01%. Example: 10 bps = 0.1%.",
    },
    "sl_pct": {
        "RU": "Stop Loss как доля от цены входа. Пример: 0.02 = 2%. Для Short учитывается в обратную сторону.",
        "EN": "Stop Loss as a fraction of entry price. Example: 0.02 = 2%. For shorts it is inverted.",
    },
    "tp_pct": {
        "RU": "Take Profit как доля от цены входа. Пример: 0.03 = 3%. Для Short учитывается в обратную сторону.",
        "EN": "Take Profit as a fraction of entry price. Example: 0.03 = 3%. For shorts it is inverted.",
    },
    "intrabar": {
        "RU": (
            "Если на одной свече могли сработать и SL и TP: что считать первым.\n"
            "sl — приоритет SL\n"
            "tp — приоритет TP\n"
            "worst — худший исход\n"
            "best — лучший исход"
        ),
        "EN": (
            "If both SL and TP are reachable within the same candle: which one is assumed first.\n"
            "sl — SL first\n"
            "tp — TP first\n"
            "worst — worst case\n"
            "best — best case"
        ),
    },
}


def tr(key: str, lang_value: str) -> str:
    return I18N.get(key, {}).get(lang_value, key)


# ---------------- helpers: reactive Markdown ----------------
def _section_title(key: str, lang_value: str, level: int = 3) -> str:
    prefix = "#" * int(level)
    text = I18N.get(key, {}).get(lang_value, key)
    return f"{prefix} {text}"


def make_section_pane(lang_widget: pn.widgets.Widget, key: str, level: int = 3) -> pn.pane.Markdown:
    def _f(l: str) -> str:
        return _section_title(key, l, level=level)

    return pn.pane.Markdown(pn.bind(_f, lang_widget), sizing_mode="stretch_width", margin=(0, 0, 6, 0))


def make_note_pane(lang_widget: pn.widgets.Widget, key: str) -> pn.pane.Markdown:
    """
    Компактная подсказка под полем (без повторения названия поля).
    """
    def _f(l: str) -> str:
        prefix = "Комментарий" if l == "RU" else "Note"
        body = I18N.get(key, {}).get(l, "")
        # light-grey, compact
        return f"<span style='color:#9aa0a6; font-size:12px'>{prefix}: {body}</span>"

    return pn.pane.Markdown(pn.bind(_f, lang_widget), sizing_mode="stretch_width", margin=(0, 0, 6, 0))


# ---------------- helpers: UI row with "?" tooltip ----------------
def labeled_widget(
    title: str,
    widget: pn.viewable.Viewable,
    lang_widget: pn.widgets.Widget,
    help_key: Optional[str] = None,
) -> pn.Column:
    """
    Рисует:
      [Title]   [?]
      [Widget]
    И устраняет задвоение: у widget должно быть name="".

    Уплотнённые отступы.
    """
    title_md = pn.pane.Markdown(f"**{title}**", margin=(0, 0, 0, 0))
    if help_key:
        tip = pn.widgets.TooltipIcon(value=HELP_FIELDS[help_key][lang_widget.value])
        head = pn.Row(title_md, pn.Spacer(), tip, sizing_mode="stretch_width", margin=(0, 0, 0, 0))
    else:
        head = pn.Row(title_md, sizing_mode="stretch_width", margin=(0, 0, 0, 0))
    return pn.Column(head, widget, sizing_mode="stretch_width", margin=(0, 0, 4, 0))

# ---------------- Trades table column titles (Tabulator.titles) ----------------
def trades_titles(lang_value: str) -> dict:
    """Display titles for Trades/Events table columns.

    Panel 1.4.x Tabulator uses `titles` mapping: {field_name: display_title}.
    Field names in the underlying DataFrame must remain stable.
    """
    lv = (lang_value or "RU").upper()
    if lv == "EN":
        return {
            "pick": "Marker on chart",
            "row_id": "Trade #",
            "event": "Type (ENTRY/CLOSE)",
            "side_label": "Position (LONG/SHORT/CLOSE)",
            "time": "Time (UTC)",
            "price": "Fill price",
            "close_reason": "Close reason",
            "gross_return": "P&L, % (Return)",
            "equity": "Equity",
        }
    # RU
    return {
        "pick": "Маркер на графике",
        "row_id": "№ сделки",
        "event": "Тип (ENTRY/CLOSE)",
        "side_label": "Позиция (LONG/SHORT/CLOSE)",
        "time": "Время (UTC)",
        "price": "Цена исполнения",
        "close_reason": "Причина закрытия",
        "gross_return": "P&L, % (Доходность)",
        "equity": "Капитал (Equity)",
    }

