# app.py (Panel / HoloViz)
from __future__ import annotations

import os
import time
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Optional, Tuple, List

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import panel as pn

import core_yaml
import ui_i18n
import data_io
import plots
import backtest_runner
import bg_jobs
import aws_indicator_pipeline
import indicators.aws_network as aws_network
import indicators


APP_TITLE = "MyBot • Бэктест (YAML / Python) — Panel"

# ---------------- Price data roots ----------------
# Project is moving price CSVs out of the repo into /opt/mybot_data.
# Keep defaults safe/backward-compatible: if /opt dirs don't exist, fall back to legacy "data".
PRICE_USDT_DIR_DEFAULT = os.environ.get("MYBOT_PRICE_USDT_DIR", "/opt/mybot_data/price_usdt")
PRICE_USD_DIR_DEFAULT = os.environ.get("MYBOT_PRICE_USD_DIR", "/opt/mybot_data/price_usd")

if os.path.isdir(PRICE_USDT_DIR_DEFAULT):
    DATA_DIR_DEFAULT = PRICE_USDT_DIR_DEFAULT
else:
    DATA_DIR_DEFAULT = os.environ.get("MYBOT_DATA_DIR", "data")
STRATEGIES_DIR_DEFAULT = "strategies"
ALLOWED_TFS = ["1m", "5m", "15m", "30m", "1H", "2H", "4H", "6H", "1D", "1W", "1M", "3M"]
DEFAULT_SYMBOLS = ["BTC/USDT", "BTC/USD"]

LOG = logging.getLogger("mybot")
if not LOG.handlers:
    logging.basicConfig(level=os.environ.get("MYBOT_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")

# --- DIAG logging (opt-in, runtime configurable) ---
# Управление параметрами вынесено в UI-блок Debug (см. ниже).
# По умолчанию берём значения из env:
#   MYBOT_DIAG=1|0
#   MYBOT_LOG_DIR=...
#   MYBOT_DIAG_MAX_BYTES=...
#   MYBOT_DIAG_BACKUPS=...
# Дополнительно (опционально):
#   MYBOT_DIAG_HEAD_N=...
#   MYBOT_DIAG_MAX_COLS=...
DIAG = os.environ.get("MYBOT_DIAG", "0") == "1"
DIAG_HEAD_N = int(os.environ.get("MYBOT_DIAG_HEAD_N", "3"))
DIAG_MAX_COLS = int(os.environ.get("MYBOT_DIAG_MAX_COLS", "30"))

APP_DIR = Path(__file__).resolve().parent
LOG_DIR = Path(os.environ.get("MYBOT_LOG_DIR", str(APP_DIR / "logs")))
DIAG_MAX_BYTES = int(os.environ.get("MYBOT_DIAG_MAX_BYTES", str(10 * 1024 * 1024)))  # 10MB
DIAG_BACKUPS = int(os.environ.get("MYBOT_DIAG_BACKUPS", "5"))

DLOG = logging.getLogger("mybot.diag")
DLOG.setLevel(logging.INFO)
DLOG.propagate = False  # avoid double logging to root handlers


def _reconfigure_diag_logging(
    *,
    enabled: bool,
    log_dir: str,
    max_bytes: int,
    backups: int,
    head_n: int,
    max_cols: int,
) -> None:
    """(Re)configure DIAG logging safely at runtime.

    Never raises: diagnostics must not break the app.
    """
    global DIAG, LOG_DIR, DIAG_MAX_BYTES, DIAG_BACKUPS, DIAG_HEAD_N, DIAG_MAX_COLS

    # Update globals first
    DIAG = bool(enabled)
    DIAG_HEAD_N = int(head_n)
    DIAG_MAX_COLS = int(max_cols)

    DIAG_MAX_BYTES = max(256 * 1024, int(max_bytes))  # min 256KB
    DIAG_BACKUPS = max(1, int(backups))

    try:
        LOG_DIR = Path(str(log_dir)).expanduser()
    except Exception:
        # keep previous LOG_DIR on parse errors
        pass

    # Remove existing rotating handlers to avoid duplicates on autoreload / reconfig
    try:
        for h in list(DLOG.handlers):
            if isinstance(h, RotatingFileHandler):
                try:
                    h.close()
                except Exception:
                    pass
                try:
                    DLOG.removeHandler(h)
                except Exception:
                    pass
    except Exception:
        pass

    if not DIAG:
        return

    # Create target dir + attach new handler
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        # If directory can't be created, silently skip diagnostics
        return

    try:
        diag_path = LOG_DIR / "mybot.diag.log"
        h = RotatingFileHandler(
            diag_path,
            maxBytes=DIAG_MAX_BYTES,
            backupCount=DIAG_BACKUPS,
            encoding="utf-8",
        )
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        h.setFormatter(fmt)
        DLOG.addHandler(h)
        try:
            DLOG.info("DIAG CONFIG | enabled=True | log_dir=%s | max_bytes=%s | backups=%s | head_n=%s | max_cols=%s", str(LOG_DIR), DIAG_MAX_BYTES, DIAG_BACKUPS, DIAG_HEAD_N, DIAG_MAX_COLS)
        except Exception:
            pass
    except Exception:
        # do not fail app if handler can't be created
        pass


# Initial configure from env (can be overridden in Debug UI later)
_reconfigure_diag_logging(
    enabled=DIAG,
    log_dir=str(LOG_DIR),
    max_bytes=DIAG_MAX_BYTES,
    backups=DIAG_BACKUPS,
    head_n=DIAG_HEAD_N,
    max_cols=DIAG_MAX_COLS,
)


def _diag(msg: str, **kv: Any) -> None:
    """Lightweight structured diagnostic logger (never raises)."""
    if not DIAG:
        return
    try:
        parts = [msg]
        for k, v in kv.items():
            parts.append(f"{k}={v!r}")
        DLOG.info(" | ".join(parts))
    except Exception:
        pass

_DIAG_LAST: Dict[str, float] = {}

def _diag_throttle(tag: str, every_sec: float = 2.0, **kv: Any) -> None:
    if not DIAG:
        return
    try:
        now = time.time()
        last = _DIAG_LAST.get(tag, 0.0)
        if now - last < every_sec:
            return
        _DIAG_LAST[tag] = now
        _diag(tag, **kv)
    except Exception:
        pass

def _diag_df_integrity(df: Optional[pd.DataFrame], name: str, **extra: Any) -> None:
    if not DIAG:
        return
    try:
        if df is None:
            _diag("DIAG DF", name=name, df=None, **extra)
            return
        if len(df) == 0:
            _diag("DIAG DF", name=name, shape=df.shape, empty=True, cols=list(df.columns)[:DIAG_MAX_COLS], **extra)
            return
        cols = list(df.columns)
        cols_short = cols[:DIAG_MAX_COLS] + (["..."] if len(cols) > DIAG_MAX_COLS else [])
        ts = df["timestamp"] if "timestamp" in df.columns else None
        ts_dtype = None if ts is None else str(ts.dtype)
        ts_min = None if ts is None else ts.min()
        ts_max = None if ts is None else ts.max()
        ts_mono = None if ts is None else bool(ts.is_monotonic_increasing)
        ts_dupes = None if ts is None else int(ts.duplicated().sum())
        nan_ohlc = None
        for c in ("open", "high", "low", "close"):
            if c in df.columns:
                if nan_ohlc is None:
                    nan_ohlc = {}
                nan_ohlc[c] = int(df[c].isna().sum())
        head = df.head(DIAG_HEAD_N).to_dict(orient="list")
        _diag(
            "DIAG DF",
            name=name,
            shape=df.shape,
            cols=cols_short,
            ts_dtype=ts_dtype,
            ts_min=ts_min,
            ts_max=ts_max,
            ts_monotonic=ts_mono,
            ts_dupes=ts_dupes,
            nan_ohlc=nan_ohlc,
            head=head,
            **extra,
        )
    except Exception:
        pass

def _diag_fig_stats(tag: str, fig: Optional[go.Figure], sec: Optional[float] = None, **extra: Any) -> None:
    if not DIAG:
        return
    try:
        if fig is None:
            _diag("DIAG FIG", tag=tag, fig=None, sec=sec, **extra)
            return
        traces = len(fig.data) if getattr(fig, "data", None) is not None else None
        shapes = 0
        annotations = 0
        try:
            shapes = len(fig.layout.shapes) if getattr(fig.layout, "shapes", None) is not None else 0
        except Exception:
            shapes = None
        try:
            annotations = len(fig.layout.annotations) if getattr(fig.layout, "annotations", None) is not None else 0
        except Exception:
            annotations = None
        # approximate point count (cheap)
        total_pts = 0
        try:
            for tr in fig.data:
                x = getattr(tr, "x", None)
                if x is not None:
                    total_pts += len(x)
        except Exception:
            total_pts = None
        _diag("DIAG FIG", tag=tag, sec=sec, traces=traces, shapes=shapes, annotations=annotations, total_pts=total_pts, **extra)
    except Exception:
        pass


pn.extension(
    "plotly",
    "tabulator",
    sizing_mode="stretch_width",
    raw_css=[
        """
        /* Sidebar: 100% ширина виджетов + нормальный скролл */
        .bk-root .bk-sidebar { overflow-y: auto !important; }
        .bk-root .bk-sidebar .bk,
        .bk-root .bk-sidebar .bk-input,
        .bk-root .bk-sidebar .bk-select,
        .bk-root .bk-sidebar .bk-btn,
        .bk-root .bk-sidebar .bk-btn-group,
        .bk-root .bk-sidebar .bk-text-input,
        .bk-root .bk-sidebar .bk-slider-title,
        .bk-root .bk-sidebar .bk-slider {
          width: 100% !important;
          max-width: 100% !important;
          box-sizing: border-box;
        }

        /* Уплотняем markdown (заголовки/подсказки) в sidebar */
        .bk-root .bk-sidebar .markdown p { margin: 0 !important; }
        .bk-root .bk-sidebar .markdown { margin: 0 0 4px 0 !important; }

        /* Моноширинный блок метрик */
        .mybot-metrics {
          background: #111;
          color: #e6e6e6;
          padding: 10px;
          border-radius: 6px;
        }
        .mybot-metrics table {
          width: 100%;
          border-collapse: collapse;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
          font-size: 12.5px;
          line-height: 1.35;
        }
        .mybot-metrics td { padding: 1px 0; vertical-align: top; }
        .mybot-metrics td.k { color: #e6e6e6; padding-right: 10px; white-space: nowrap; }
        .mybot-metrics td.v { color: #e6e6e6; padding-right: 14px; white-space: nowrap; }
        .mybot-metrics td.c { color: #9aa0a6; }
        """
    ],
)

# ---------------- i18n widgets (source of truth) ----------------
lang = pn.widgets.RadioButtonGroup(name="Language", options=ui_i18n.LANGS, value="RU", button_type="default", visible=False)


def tr(key: str) -> str:
    return ui_i18n.tr(key, lang.value)


# Custom language switch (flags) in header
lang_ru_btn = pn.widgets.Button(name="🇷🇺 RU", button_type="primary", width=84, height=30)
lang_en_btn = pn.widgets.Button(name="🇬🇧 EN", button_type="default", width=84, height=30)
lang_switch = pn.Row(lang_ru_btn, lang_en_btn, sizing_mode="fixed", width=190, height=32, margin=(0, 0, 0, 0))

# WebSocket/Session heartbeat (UI hint).
# Updates periodically; if time stops changing, client likely lost WS connection.
ws_status_pane = pn.pane.HTML("", sizing_mode="fixed", width=220, margin=(0, 8, 0, 0))
_ws_last = {"t": 0.0}

def _ws_tick() -> None:
    try:
        import datetime as _dt
        _ws_last["t"] = time.time()
        ts = _dt.datetime.utcnow().strftime("%H:%M:%S")
        ws_status_pane.object = f"<span style='color:#2e7d32;font-weight:700'>●</span> WS {ts} UTC"
    except Exception:
        pass


def _sync_lang_buttons(*_events) -> None:
    if lang.value == "RU":
        lang_ru_btn.button_type = "primary"
        lang_en_btn.button_type = "default"
    else:
        lang_ru_btn.button_type = "default"
        lang_en_btn.button_type = "primary"


def _set_lang_ru(_event=None) -> None:
    lang.value = "RU"


def _set_lang_en(_event=None) -> None:
    lang.value = "EN"


lang_ru_btn.on_click(_set_lang_ru)
lang_en_btn.on_click(_set_lang_en)

# ---------------- status ----------------
status = pn.pane.Alert("", alert_type="info", visible=False)

# Debug: защита от "залипания" (когда .disabled остаётся True из-за рассинхрона/потери патча).
# ВАЖНО: При включении мы НЕ блокируем кнопки (тяжёлая логика и так защищена токенами/guard'ами).
debug_antistick = pn.widgets.Checkbox(
    name="Debug: защита от залипания (НЕ блокировать disabled)",
    value=True,
)

# Debug: DIAG logging controls (runtime)
# Эти поля отражают значения env-переменных, но управляются из UI.
debug_diag_enable = pn.widgets.Checkbox(
    name="Debug: DIAG logging (mybot.diag.log, rotated)",
    value=DIAG,
)

debug_log_dir = pn.widgets.TextInput(
    name="MYBOT_LOG_DIR",
    value=str(LOG_DIR),
    placeholder="mybot/logs",
)

debug_diag_max_bytes = pn.widgets.IntInput(
    name="MYBOT_DIAG_MAX_BYTES",
    value=int(DIAG_MAX_BYTES),
    start=256 * 1024,
    step=1024 * 1024,
)

debug_diag_backups = pn.widgets.IntInput(
    name="MYBOT_DIAG_BACKUPS",
    value=int(DIAG_BACKUPS),
    start=1,
    step=1,
)

# Опциональные параметры (как env):
debug_diag_head_n = pn.widgets.IntInput(
    name="MYBOT_DIAG_HEAD_N",
    value=int(DIAG_HEAD_N),
    start=0,
    step=1,
)

debug_diag_max_cols = pn.widgets.IntInput(
    name="MYBOT_DIAG_MAX_COLS",
    value=int(DIAG_MAX_COLS),
    start=1,
    step=1,
)

debug_apply_diag = pn.widgets.Button(
    name="Apply DIAG settings",
    button_type="primary",
)


debug_ping_diag = pn.widgets.Button(
    name="Write DIAG ping",
    button_type="default",
)

debug_diag_state = pn.pane.Markdown("", sizing_mode="stretch_width")

def _render_diag_state() -> None:
    try:
        path = str(LOG_DIR / "mybot.diag.log")
        md = "\n".join(
            [
                f"**DIAG enabled:** `{DIAG}`",
                f"**MYBOT_LOG_DIR:** `{str(LOG_DIR)}`",
                f"**MYBOT_DIAG_MAX_BYTES:** `{DIAG_MAX_BYTES}`",
                f"**MYBOT_DIAG_BACKUPS:** `{DIAG_BACKUPS}`",
                f"**MYBOT_DIAG_HEAD_N:** `{DIAG_HEAD_N}`",
                f"**MYBOT_DIAG_MAX_COLS:** `{DIAG_MAX_COLS}`",
                f"**File:** `{path}`",
                "",
                "**Tail command:**",
                f"```bash\ntail -f {path}\n```",
            ]
        )
        debug_diag_state.object = md
    except Exception:
        pass

def _apply_diag_settings(_event=None) -> None:
    try:
        _reconfigure_diag_logging(
            enabled=bool(debug_diag_enable.value),
            log_dir=str(debug_log_dir.value),
            max_bytes=int(debug_diag_max_bytes.value),
            backups=int(debug_diag_backups.value),
            head_n=int(debug_diag_head_n.value),
            max_cols=int(debug_diag_max_cols.value),
        )
    except Exception:
        # never break the app due to debug tooling
        pass
    _render_diag_state()



def _ping_diag(_event=None) -> None:
    """Emit a single DIAG line to validate logging pipeline (never raises)."""
    try:
        _diag("DIAG PING", ts=round(time.time(), 3), pid=os.getpid())
    except Exception:
        pass
    _render_diag_state()

# Apply button + quick toggle on enable/disable
debug_apply_diag.on_click(_apply_diag_settings)
debug_ping_diag.on_click(_ping_diag)
debug_diag_enable.param.watch(lambda e: _apply_diag_settings(), "value")

# Render initial state
_render_diag_state()

debug_card = pn.Card(
    pn.pane.Markdown("**Debug**"),
    debug_antistick,
    pn.layout.Divider(),
    debug_diag_enable,
    debug_log_dir,
    pn.Row(debug_diag_max_bytes, debug_diag_backups),
    pn.Row(debug_diag_head_n, debug_diag_max_cols),
    debug_apply_diag,
    debug_ping_diag,
    debug_diag_state,
    collapsed=True,
    title="Debug",
)



def _set_status(msg: str, kind: str = "info") -> None:
    status.object = msg
    status.alert_type = kind
    status.visible = bool(msg)


# ---------------- caches / last state ----------------
_bt_cache: Dict[str, backtest_runner.BacktestResult] = {}

_last_run: Optional[Dict[str, Any]] = None
# keys: res, dt_from, dt_to, strategy_lang, ctx_sig, bt_from, bt_to

_last_trades_events_df: Optional[pd.DataFrame] = None

_last_df_show: Optional[pd.DataFrame] = None  # cached df_show for PRICE redraw
_last_ctx_sig: Optional[Tuple[Any, ...]] = None  # last backtest ctx signature (strategy validity)
_last_price_ctx_sig: Optional[Tuple[Any, ...]] = None  # last PRICE ctx signature (df_show cache validity)

_highlight_time: Optional[pd.Timestamp] = None
_highlight_label: Optional[str] = None

# Trades checkbox selection -> vertical highlight
_picked_row_id: Optional[int] = None
_last_picked_set: set[int] = set()
_pick_update_guard: bool = False

# Backtest range memory per strategy (Python per file, YAML shared)
_bt_range_mem: Dict[Tuple[str, str], Tuple[str, str]] = {}


# ---------------- Indicators layer (separate from strategy overlays) ----------------
# Params and caches live in UI layer so that trade-row highlighting does NOT recompute indicators every time.
_ind_params_state: Dict[str, Dict[str, Any]] = {}  # {indicator_id: {param: value}}
_ind_cache: Dict[Any, Any] = {}  # key -> indicators.IndicatorBundle


# ---------------- background executor ----------------
_EXEC = ThreadPoolExecutor(max_workers=3)
_job_lock = threading.Lock()
_job_seq = 0
_job_running = False


def _ui_call(fn) -> None:
    """Run fn in Bokeh/Panel UI thread."""
    try:
        doc = pn.state.curdoc
        if doc is None:
            fn()
            return
        doc.add_next_tick_callback(fn)
    except Exception:
        fn()



# --- Busy state (race-safe) ---
_busy_lock = threading.Lock()
_busy_tokens: set[int] = set()
_busy_token_next: int = 0
_busy_seq: int = 0


def _busy_begin(msg: str = "") -> int:
    """Enter busy state and return a token. Busy state ends when the token is released."""
    global _busy_token_next, _busy_seq
    with _busy_lock:
        _busy_token_next += 1
        token = _busy_token_next
        _busy_tokens.add(token)
        _busy_seq += 1
        seq = _busy_seq
        count = len(_busy_tokens)

    def _apply():
        # drop out-of-order UI callbacks
        if seq != _busy_seq:
            return
        is_busy = count > 0
        # Если включена защита от "залипания" — НЕ трогаем .disabled.
        # Если выключена — блокируем кнопки на время выполнения.
        lock_buttons = not bool(getattr(debug_antistick, "value", True))
        if not lock_buttons:
            # Anti-stick mode: кнопки не блокируем
            run_btn.disabled = False
            clean_btn.disabled = False
            redraw_btn.disabled = False
            clear_overlays_btn.disabled = False
            bt_use_display_btn.disabled = False
            return

        run_btn.disabled = is_busy
        redraw_btn.disabled = is_busy
        clean_btn.disabled = is_busy
        clear_overlays_btn.disabled = is_busy
        bt_use_display_btn.disabled = is_busy
        if msg:
            _set_status(msg, "info")

    _ui_call(_apply)
    return token


def _busy_end(token: Optional[int]) -> None:
    """Leave busy state for a given token."""
    global _busy_seq
    if token is None:
        return
    with _busy_lock:
        _busy_tokens.discard(int(token))
        _busy_seq += 1
        seq = _busy_seq
        count = len(_busy_tokens)

    def _apply():
        if seq != _busy_seq:
            return
        is_busy = count > 0
        lock_buttons = not bool(getattr(debug_antistick, "value", True))
        if not lock_buttons:
            # Anti-stick mode: кнопки не блокируем
            run_btn.disabled = False
            clean_btn.disabled = False
            redraw_btn.disabled = False
            clear_overlays_btn.disabled = False
            bt_use_display_btn.disabled = False
            return

        run_btn.disabled = is_busy
        redraw_btn.disabled = is_busy
        clean_btn.disabled = is_busy
        clear_overlays_btn.disabled = is_busy
        bt_use_display_btn.disabled = is_busy

    _ui_call(_apply)


def _set_busy(is_busy: bool, msg: str = "") -> None:
    """Legacy helper: prefer _busy_begin/_busy_end."""
    global _legacy_busy_token
    try:
        _legacy_busy_token
    except NameError:
        _legacy_busy_token = None  # type: ignore
    if is_busy:
        if _legacy_busy_token is None:
            _legacy_busy_token = _busy_begin(msg)
        else:
            # update message only
            if msg:
                _ui_call(lambda: _set_status(msg, "info"))
    else:
        tok = _legacy_busy_token
        _legacy_busy_token = None
        _busy_end(tok)


# ---------------- UI widgets ----------------
data_source = pn.widgets.RadioButtonGroup(
    name=tr("src"),
    options=[tr("disk"), tr("upload")],
    button_type="default",
    value=tr("disk"),
)
data_dir = pn.widgets.TextInput(name=tr("data_dir"), value=DATA_DIR_DEFAULT)
csv_select = pn.widgets.Select(name=tr("csv"), options=[])
upload = pn.widgets.FileInput(name=tr("upload"), accept=".csv")

symbol = pn.widgets.Select(name=tr("symbol"), options=DEFAULT_SYMBOLS, value=DEFAULT_SYMBOLS[0])
tf = pn.widgets.Select(name=tr("tf"), options=ALLOWED_TFS, value="1H")

# display dates (TextInput)
date_from = pn.widgets.TextInput(name=tr("date_from"), value="2022-01-01")
date_to = pn.widgets.TextInput(name=tr("date_to"), value="")

warmup_bars = pn.widgets.IntInput(name=tr("warmup"), value=0, start=0, end=50000, step=50)


# Indicators (new layer)
ind_select = pn.widgets.CheckBoxGroup(name=tr("ind_select"), options={}, value=[])
ind_max_points = pn.widgets.IntInput(name=tr("ind_max_points"), value=8000, start=1000, end=50000, step=500)
ind_clear_btn = pn.widgets.Button(name=tr("ind_clear"), button_type="default")
ind_note = pn.pane.Markdown("", sizing_mode="stretch_width", margin=(0, 0, 6, 0))
ind_params_panel = pn.Column(sizing_mode="stretch_width", margin=(0, 0, 0, 0))

# DISPLAY settings
chart_mode = pn.widgets.Select(name=tr("chart_mode"), options=["Line", "Candles (B/W)", "Heatmap"], value="Line")
max_points = pn.widgets.IntInput(name=tr("max_points"), value=200000, start=500, end=200000, step=500)

hm_time_bins = pn.widgets.IntInput(name=tr("hm_tb"), value=450, start=50, end=1200, step=50)
hm_price_bins = pn.widgets.IntInput(name=tr("hm_pb"), value=140, start=50, end=300, step=10)

# STRATEGY selection
strategy_lang = pn.widgets.RadioButtonGroup(name=tr("strat_lang"), options=["YAML", "Python"], value="Python")
strategies_dir = pn.widgets.TextInput(name=tr("strat_dir"), value=STRATEGIES_DIR_DEFAULT)
py_select = pn.widgets.Select(name=tr("py_strat"), options=[])

yaml_text = pn.widgets.TextAreaInput(name=tr("yaml_strat"), value=core_yaml.DEFAULT_YAML, height=360)

# Backtest window (separate from display range)
bt_from = pn.widgets.TextInput(name="", value="")
bt_to = pn.widgets.TextInput(name="", value="")
bt_note = pn.pane.Markdown("", sizing_mode="stretch_width", margin=(0, 0, 6, 0))
bt_use_display_btn = pn.widgets.Button(name="", button_type="default")
clear_overlays_btn = pn.widgets.Button(name="", button_type="default")

# PY mode toggles
allow_long = pn.widgets.Checkbox(name=tr("allow_long"), value=True)
allow_short = pn.widgets.Checkbox(name=tr("allow_short"), value=True)
reverse_logic = pn.widgets.Checkbox(name=tr("reverse"), value=False)

ov_length = pn.widgets.IntInput(name=tr("length"), value=16, start=1, end=500, step=1)
ov_extreme = pn.widgets.IntInput(name=tr("extreme"), value=16, start=1, end=500, step=1)
ov_corr = pn.widgets.FloatInput(name=tr("corr"), value=0.0, start=-100.0, end=100.0, step=0.1)

# PoP Reversal Strategy (Pivot of Pivot) inputs
pop_left_bars = pn.widgets.IntInput(name=tr("pop_left_bars"), value=4, start=1, end=50, step=1)
pop_right_bars = pn.widgets.IntInput(name=tr("pop_right_bars"), value=2, start=1, end=50, step=1)
pop_atr_length = pn.widgets.IntInput(name=tr("pop_atr_length"), value=14, start=1, end=500, step=1)
pop_atr_mult = pn.widgets.FloatInput(name=tr("pop_atr_mult"), value=0.1, start=0.0, end=10.0, step=0.01)
pop_min_tick = pn.widgets.FloatInput(name=tr("pop_min_tick"), value=0.1, start=0.0, end=10.0, step=0.0001)

# PoP execution model (bot-like)
pop_real_trade = pn.widgets.Checkbox(name=tr("pop_real_trade"), value=True)
pop_exec_model = pn.widgets.Select(
    name=tr("exec_model"),
    options={
        "deterministic": tr("exec_det"),
        "conservative": tr("exec_cons"),
    },
    value="deterministic",
)
fishnet_filter = pn.widgets.Checkbox(name=tr("fishnet_filter"), value=True)
fishnet_tf = pn.widgets.Select(name=tr("fishnet_tf"), options=["same", "1D", "4H", "6H"], value="1D")
fishnet_start_len = pn.widgets.IntInput(name=tr("fishnet_start_len"), value=10, start=1, end=500, step=1)
fishnet_step = pn.widgets.IntInput(name=tr("fishnet_step"), value=10, start=1, end=500, step=1)
fishnet_count = pn.widgets.IntInput(name=tr("fishnet_count"), value=20, start=2, end=60, step=1)
fishnet_show = pn.widgets.Checkbox(name=tr("fishnet_show"), value=False)
fishnet_opacity = pn.widgets.FloatSlider(name=tr("fishnet_opacity"), start=0.05, end=1.0, step=0.05, value=0.35)
fishnet_width = pn.widgets.IntInput(name=tr("fishnet_width"), value=1, start=1, end=6, step=1)
fishnet_color_up = pn.widgets.TextInput(name=tr("fishnet_color_up"), value="#00FF7F")
fishnet_color_dn = pn.widgets.TextInput(name=tr("fishnet_color_dn"), value="#DC143C")


# --- Capital / fee / slippage / SL / TP (IMPORTANT: name="" to avoid duplication) ---
initial_capital = pn.widgets.FloatInput(name="", value=1000.0, start=0.0, end=1e12, step=100.0)
no_reinvest = pn.widgets.Checkbox(name="", value=False)
fee_pct = pn.widgets.FloatInput(name="", value=0.0, start=0.0, end=0.01, step=0.0001)
slippage_bps = pn.widgets.FloatInput(name="", value=0.0, start=0.0, end=200.0, step=0.1)
sl_pct = pn.widgets.FloatInput(name="", value=0.0, start=0.0, end=0.5, step=0.001)
tp_pct = pn.widgets.FloatInput(name="", value=0.0, start=0.0, end=1.0, step=0.001)
intrabar = pn.widgets.Select(name="", options=["sl", "tp", "worst", "best"], value="sl")

PINE_INPUTS_BY_PY_STRATEGY = {
    "pine_v5_zz2.py": "/root/mybot/strategies/zz2_inputs.pine",
    "pop_reversal.py": "/root/mybot/strategies/pop_inputs.pine",
}
PINE_INPUTS_DEFAULT = "/root/mybot/strategies/zz2_inputs.pine"

pine_inputs_path = PINE_INPUTS_DEFAULT
pine_text = pn.widgets.TextAreaInput(name="Pine script (inputs)", value="", height=180)

# Chart overlays
show_trades = pn.widgets.Checkbox(name=tr("show_trades"), value=True)
show_entries = pn.widgets.Checkbox(name=tr("show_entries"), value=True)
show_exits = pn.widgets.Checkbox(name=tr("show_exits"), value=True)
show_uplevel = pn.widgets.Checkbox(name=tr("show_uplevel"), value=False)
show_dnlevel = pn.widgets.Checkbox(name=tr("show_dnlevel"), value=False)
show_break = pn.widgets.Checkbox(name=tr("show_break"), value=False)
show_pop_pivots = pn.widgets.Checkbox(name=tr("show_pop_pivots"), value=True)
show_pop_levels = pn.widgets.Checkbox(name=tr("show_pop_levels"), value=True)

# Price axis scale
price_log = pn.widgets.Checkbox(name=tr("price_log"), value=False)

run_btn = pn.widgets.Button(name=tr("run"), button_type="primary")
redraw_btn = pn.widgets.Button(name=tr("redraw"), button_type="default")
clean_btn = pn.widgets.Button(name="", button_type="default")

price_plot = pn.pane.Plotly(height=620, sizing_mode="stretch_width")
equity_plot = pn.pane.Plotly(height=260, sizing_mode="stretch_width")

metrics_box = pn.pane.HTML('<div class="mybot-metrics"></div>', sizing_mode="stretch_width")

# Trades now shows EVENTS (ENTRY/CLOSE)
trades_table = pn.widgets.Tabulator(
    pd.DataFrame(),
    height=300,
    sizing_mode="stretch_width",
    selectable=0,
    show_index=False,
    pagination="local",
    page_size=50,
    formatters={"pick": "tickCross", "side_label": "html"},
    editors={"pick": "tickCross"},
    hidden_columns=["side_label_raw", "trade_id"],
)
try:
    trades_table.titles = ui_i18n.trades_titles(lang.value)
except Exception:
    pass


# --- Tabulator safe updates (avoid JS races on setColumns/destroy/setMaxPage) ---
def _set_trades_table_df(df: Optional[pd.DataFrame]) -> None:
    """Update trades_table.value, then reset pagination/selection on next tick.

    This reduces client-side Tabulator race conditions when the table is being reconfigured.
    """
    global _picked_row_id, _last_picked_set, _pick_update_guard

    trades_table.value = df if isinstance(df, pd.DataFrame) else pd.DataFrame()

    def _after() -> None:
        global _picked_row_id, _last_picked_set, _pick_update_guard
        _picked_row_id = None
        _last_picked_set = set()
        _pick_update_guard = True
        try:
            if hasattr(trades_table, "page"):
                trades_table.page = 1
        except Exception:
            pass
        try:
            trades_table.selection = []
        except Exception:
            pass
        _pick_update_guard = False

    _ui_call(_after)


equity_table = pn.widgets.Tabulator(pd.DataFrame(), height=260, sizing_mode="stretch_width", show_index=False)

# ---------------- UI support ----------------
def _refresh_csv_list() -> None:
    d = data_dir.value.strip() or DATA_DIR_DEFAULT
    options = data_io.refresh_csv_options(d)
    prev = csv_select.value
    csv_select.options = options
    if prev in options:
        csv_select.value = prev
    elif options:
        csv_select.value = options[0]
    else:
        csv_select.value = None


def _refresh_py_list() -> None:
    d = strategies_dir.value.strip() or STRATEGIES_DIR_DEFAULT
    if not os.path.isdir(d):
        py_select.options = []
        py_select.value = None
        return
    mp = backtest_runner.list_py_strategies(d)
    py_select.options = list(mp.keys())
    py_select.value = py_select.options[0] if py_select.options else None


def _current_pine_inputs_path() -> str:
    if str(strategy_lang.value) != "Python":
        return pine_inputs_path
    sel = str(py_select.value or "")
    return PINE_INPUTS_BY_PY_STRATEGY.get(sel, PINE_INPUTS_DEFAULT)


def _load_pine_defaults() -> None:
    global pine_inputs_path
    pine_inputs_path = _current_pine_inputs_path()
    if os.path.exists(pine_inputs_path):
        try:
            pine_text.value = data_io.read_text(pine_inputs_path)
        except Exception as e:
            _set_status(f"Pine inputs: ошибка чтения {pine_inputs_path}: {e}", "warning")
    else:
        _set_status(f"Pine inputs: файл не найден: {pine_inputs_path}", "warning")


def _on_tf_change(event=None) -> None:
    _refresh_csv_list()
    picked = data_io.pick_csv_for_tf(tf.value, list(csv_select.options))
    if picked is not None:
        csv_select.value = picked


# ---------------- Symbol presets (BTC/USDT vs BTC/USD) ----------------
# Goal: switching symbol should automatically point to the correct price directory and the longest history.
_SYMBOL_CTX_MEM: Dict[str, Dict[str, str]] = {}
_SYMBOL_DEFAULTS: Dict[str, Dict[str, str]] = {
    "BTC/USDT": {
        "data_dir": PRICE_USDT_DIR_DEFAULT,
        "csv": "btc_usdt_1D.csv",
        "tf": "1D",
        "date_from": "2018-01-01",
    },
    "BTC/USD": {
        "data_dir": PRICE_USD_DIR_DEFAULT,
        "csv": "btc_usd_1D.csv",
        "tf": "1D",
        "date_from": "2010-07-19",
    },
}

_LAST_SYMBOL = str(DEFAULT_SYMBOLS[0])


def _apply_tf_constraints(sym: str) -> None:
    """Restrict TF list per symbol (safe UI-only).

    - BTC/USD: only 1D (current data source provides daily only).
    - BTC/USDT: full TF list.
    """
    try:
        if sym == "BTC/USD":
            tf.options = ["1D"]
            tf.value = "1D"
        else:
            tf.options = ALLOWED_TFS
            if str(tf.value) not in list(tf.options):
                tf.value = "1D"
    except Exception:
        pass


def _apply_symbol_preset(sym: str) -> None:
    """Apply safe defaults for a given symbol (never raises)."""
    try:
        preset = _SYMBOL_DEFAULTS.get(sym)
        if not preset:
            return

        # Apply TF constraints + set TF
        _apply_tf_constraints(sym)
        if preset.get("tf") and str(preset.get("tf")) in list(tf.options):
            tf.value = preset.get("tf", tf.value)

        # Default price scale per symbol
        try:
            price_log.value = bool(preset.get("price_log", False))
        except Exception:
            pass

        # If data_dir exists, switch to it
        d = preset.get("data_dir", "")
        if d and os.path.isdir(d):
            data_dir.value = d

        _refresh_csv_list()

        # Try preferred CSV first; otherwise use heuristic picker
        want = preset.get("csv", "")
        if want and want in list(csv_select.options):
            csv_select.value = want
        else:
            picked = data_io.pick_csv_for_tf(tf.value, list(csv_select.options))
            if picked is not None:
                csv_select.value = picked

        # Ensure early history for BTC/USD
        df0 = preset.get("date_from", "")
        if df0:
            date_from.value = df0
            # show full range by default
            date_to.value = ""
    except Exception as e:
        LOG.warning("symbol preset failed: %s", e)


def _on_symbol_change(event=None) -> None:
    """Remember per-symbol context and switch to the right price root."""
    global _LAST_SYMBOL
    try:
        new_sym = str(symbol.value or "").strip() or "BTC/USDT"
        old_sym = str(_LAST_SYMBOL or "").strip()

        # Save current context for old symbol
        if old_sym:
            _SYMBOL_CTX_MEM[old_sym] = {
                "data_dir": str(data_dir.value or "").strip(),
                "csv": str(csv_select.value or "").strip(),
                "tf": str(tf.value or "").strip(),
                "date_from": str(date_from.value or "").strip(),
                "date_to": str(date_to.value or "").strip(),
                "price_log": "1" if bool(getattr(price_log, "value", False)) else "0",
            }

        # Restore context if we have it; otherwise apply preset
        # Apply TF constraints for the NEW symbol before restoring tf.value
        _apply_tf_constraints(new_sym)

        ctx = _SYMBOL_CTX_MEM.get(new_sym)
        if ctx:
            if "price_log" in ctx:
                try:
                    price_log.value = (str(ctx.get("price_log")) == "1")
                except Exception:
                    pass

            if ctx.get("tf") and str(ctx.get("tf")) in list(tf.options):
                tf.value = ctx["tf"]
            if ctx.get("data_dir") and os.path.isdir(ctx["data_dir"]):
                data_dir.value = ctx["data_dir"]
            _refresh_csv_list()
            if ctx.get("csv") and ctx["csv"] in list(csv_select.options):
                csv_select.value = ctx["csv"]
            if ctx.get("date_from"):
                date_from.value = ctx["date_from"]
            if "date_to" in ctx:
                date_to.value = ctx["date_to"]
        else:
            _apply_symbol_preset(new_sym)

        _LAST_SYMBOL = new_sym
    except Exception as e:
        LOG.exception("symbol change handler failed: %s", e)


def _ctx_signature() -> Tuple[Any, ...]:
    """Signature of 'data context' that affects df_show / strategy applicability."""
    src = "disk" if data_source.value == tr("disk") else "upload"
    return (
        src,
        (data_dir.value or "").strip(),
        (csv_select.value or "").strip(),
        getattr(upload, "filename", "") or "",
        len(upload.value) if isinstance(upload.value, (bytes, bytearray)) else 0,
        (date_from.value or "").strip(),
        (date_to.value or "").strip(),
        (tf.value or "").strip(),
        int(warmup_bars.value or 0),
    )


def _bt_key() -> Tuple[str, str]:
    """Key for remembering backtest ranges."""
    if str(strategy_lang.value) == "Python":
        return ("Python", str(py_select.value or ""))
    return ("YAML", "YAML")


def _load_bt_range_for_current_strategy() -> None:
    k = _bt_key()
    if k in _bt_range_mem:
        f, t = _bt_range_mem[k]
        bt_from.value = f
        bt_to.value = t


def _save_bt_range_for_current_strategy() -> None:
    k = _bt_key()
    _bt_range_mem[k] = ((bt_from.value or "").strip(), (bt_to.value or "").strip())


def _use_display_range_for_bt(_event=None) -> None:
    bt_from.value = (date_from.value or "").strip()
    bt_to.value = (date_to.value or "").strip()
    _set_status(
        "Окно бэктеста взято из диапазона графика." if lang.value == "RU" else "Backtest window copied from display range.",
        "success",
    )


def _parse_dt(text: str) -> Optional[pd.Timestamp]:
    s = (text or "").strip()
    if not s:
        return None
    try:
        dt = pd.to_datetime(s, utc=True, errors="coerce")
        if pd.isna(dt):
            return None
        return dt
    except Exception:
        return None


def _get_data() -> Tuple[pd.DataFrame, pd.DataFrame, Tuple[Any, ...]]:

    t0 = time.time()
    src = "disk" if data_source.value == tr("disk") else "upload"

    df_warm, df_show, data_sig, warn = data_io.get_data(
        source=src,
        data_dir=data_dir.value,
        csv_filename=csv_select.value,
        upload_bytes=upload.value,
        upload_filename=getattr(upload, "filename", "") or "",
        date_from_text=date_from.value,
        date_to_text=date_to.value,
        tf=tf.value,
        warmup_bars=int(warmup_bars.value),
        data_dir_default=DATA_DIR_DEFAULT,
        lang_value=lang.value,
    )
    if warn:
        _set_status(warn, "warning")

    t1 = time.time()
    _diag(
        "DIAG DATA",
        src=src,
        tf=tf.value,
        date_from=date_from.value,
        date_to=date_to.value,
        warmup_bars=int(warmup_bars.value),
        df_warm_shape=(None if df_warm is None else df_warm.shape),
        df_show_shape=(None if df_show is None else df_show.shape),
        data_sig=data_sig,
        warn=warn,
        sec=round(t1 - t0, 3),
    )
    _diag_df_integrity(df_show, "df_show", tf=tf.value, date_from=date_from.value, date_to=date_to.value)
    return df_warm, df_show, data_sig


def _fmt_float(v: Any) -> str:
    try:
        x = float(v)
        return f"{x:.6f}".rstrip("0").rstrip(".")
    except Exception:
        return str(v)


def _metrics_rows(metrics: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    m = metrics or {}
    help_map = ui_i18n.HELP_METRICS.get(lang.value, {})

    order = [
        "Final Equity",
        "Total Return",
        "Max Drawdown",
        "Sharpe (rough)",
        "Trades",
        "Win Rate",
        "Fee",
        "Slippage",
        "Initial Capital (USD)",
        "Final Balance (USD)",
    ]

    rows: List[Tuple[str, str, str]] = []
    for k in order:
        if k in m:
            rows.append((k, _fmt_float(m.get(k)), str(help_map.get(k, ""))))

    params = m.get("Params", {}) if isinstance(m.get("Params", {}), dict) else {}
    if params and "intrabar_priority" in params:
        rows.append(("intrabar_priority", str(params.get("intrabar_priority")), str(help_map.get("intrabar_priority", ""))))

    return rows


def _render_metrics_block(metrics: Dict[str, Any]) -> None:
    rows = _metrics_rows(metrics)

    html_rows = []
    for k, v, c in rows:
        html_rows.append(
            "<tr>"
            f"<td class='k'>{pn.util.escape(str(k))}:</td>"
            f"<td class='v'>{pn.util.escape(str(v))}</td>"
            f"<td class='c'>{pn.util.escape(str(c))}</td>"
            "</tr>"
        )

    html = "<div class='mybot-metrics'><table>" + "".join(html_rows) + "</table></div>"
    metrics_box.object = html


def _side_label_html(lbl: str) -> str:
    lbl = (lbl or "").upper()
    if lbl == "LONG":
        color = "green"
    elif lbl == "SHORT":
        color = "red"
    else:
        color = "deepskyblue"
    return f"<span style='font-weight:600; color:{color}'>{pn.util.escape(lbl)}</span>"


def _make_trades_events(trades_df: pd.DataFrame) -> pd.DataFrame:
    cols = ["pick", "row_id", "trade_id", "event", "side_label", "side_label_raw", "time", "price", "close_reason", "gross_return", "equity"]
    if not isinstance(trades_df, pd.DataFrame) or len(trades_df) == 0:
        return pd.DataFrame(columns=cols)

    t = trades_df.copy()
    for c in ["entry_time", "exit_time"]:
        if c in t.columns:
            t[c] = pd.to_datetime(t[c], utc=True, errors="coerce")
    for c in ["entry_price", "exit_price"]:
        if c in t.columns:
            t[c] = pd.to_numeric(t[c], errors="coerce")

    if "side" in t.columns:
        t["side"] = pd.to_numeric(t["side"], errors="coerce").fillna(0).astype(int)
    else:
        t["side"] = 1

    out_rows: List[Dict[str, Any]] = []
    for i, r in t.reset_index(drop=True).iterrows():
        side = int(r.get("side", 0))
        side_entry = "LONG" if side == 1 else ("SHORT" if side == -1 else "LONG")

        et = r.get("entry_time")
        ep = r.get("entry_price")
        if pd.notna(et) and pd.notna(ep):
            out_rows.append(
                {
                    "trade_id": int(i),
                    "event": "ENTRY",
                    "side_label_raw": side_entry,
                    "side_label": _side_label_html(side_entry),
                    "time": et,
                    "price": float(ep),
                    "close_reason": "",
                    "gross_return": "",
                    "equity": "",
                }
            )

        xt = r.get("exit_time")
        xp = r.get("exit_price")
        if pd.notna(xt) and pd.notna(xp):
            out_rows.append(
                {
                    "trade_id": int(i),
                    "event": "CLOSE",
                    "side_label_raw": "CLOSE",
                    "side_label": _side_label_html("CLOSE"),
                    "time": xt,
                    "price": float(xp),
                    "close_reason": str(r.get("close_reason", "") or r.get("reason", "") or ""),
                    "gross_return": _fmt_float(r.get("gross_return", "")) if "gross_return" in t.columns else "",
                    "equity": _fmt_float(r.get("equity", "")) if "equity" in t.columns else "",
                }
            )

    df = pd.DataFrame(out_rows)
    if len(df) == 0:
        return pd.DataFrame(columns=cols)

    df = df.sort_values(["time", "event"]).reset_index(drop=True)
    # Keep 'time' as string for Tabulator/JSON stability (avoid dtype churn warnings)
    df["time"] = pd.to_datetime(df["time"], utc=True, errors="coerce")
    df["time"] = df["time"].dt.strftime("%Y-%m-%dT%H:%M:%SZ").fillna("")
    df.insert(0, "pick", False)
    df.insert(1, "row_id", np.arange(1, len(df) + 1, dtype=int))
    return df


def _clear_view(reason: str = "") -> None:
    global _last_run, _last_trades_events_df
    global _last_df_show, _last_ctx_sig, _last_price_ctx_sig
    global _highlight_time, _highlight_label, _picked_row_id, _last_picked_set, _pick_update_guard

    _last_run = None
    _last_trades_events_df = None
    _last_df_show = None
    _last_ctx_sig = None
    _last_price_ctx_sig = None

    _highlight_time = None
    _highlight_label = None
    _picked_row_id = None
    _last_picked_set = set()
    _pick_update_guard = False

    _set_trades_table_df(None)
    equity_table.value = pd.DataFrame()
    price_plot.object = go.Figure()
    equity_plot.object = go.Figure()
    _render_metrics_block({})

    if reason:
        _set_status(reason, "warning")


def _clear_strategy_overlays(event=None) -> None:
    """Keep PRICE chart as-is, but clear strategy artifacts (equity/trades/metrics/last_run)."""
    global _last_run, _last_ctx_sig, _last_trades_events_df
    global _highlight_time, _highlight_label, _picked_row_id, _last_picked_set, _pick_update_guard

    with _job_lock:
        if _job_running:
            _set_status(
                "Считаю в фоне — дождитесь завершения." if lang.value == "RU"
                else "Background compute is running — please wait.",
                "warning",
            )
            return

    _last_run = None
    _last_ctx_sig = None
    _last_trades_events_df = None

    _highlight_time = None
    _highlight_label = None
    _picked_row_id = None
    _last_picked_set = set()
    _pick_update_guard = False

    _set_trades_table_df(None)
    equity_table.value = pd.DataFrame()
    equity_plot.object = go.Figure()
    _render_metrics_block({})

    _set_status(
        "Оверлеи стратегии очищены (цена сохранена)." if lang.value == "RU"
        else "Strategy overlays cleared (price preserved).",
        "success",
    )


def _show_flags_dict() -> Dict[str, bool]:
    return {
        "show_trades": bool(show_trades.value),
        "show_entries": bool(show_entries.value),
        "show_exits": bool(show_exits.value),
        "show_uplevel": bool(show_uplevel.value),
        "show_dnlevel": bool(show_dnlevel.value),
        "show_break": bool(show_break.value),
        "show_pop_pivots": bool(show_pop_pivots.value),
        "show_pop_levels": bool(show_pop_levels.value),
        "show_pop_fishnet": bool(fishnet_show.value),
    }

def _apply_price_axis_scale(_event=None) -> None:
    """Apply log/linear scaling to the PRICE axis without recomputing data.

    Safe UI-only update: modifies the current Plotly figure in-place (best-effort).
    """
    try:
        fig = getattr(price_plot, 'object', None)
        if fig is None:
            return
        if isinstance(fig, go.Figure):
            fig.update_layout(yaxis=dict(type=('log' if bool(getattr(price_log,'value',False)) else 'linear')))
            price_plot.object = fig
    except Exception:
        pass





def _fishnet_style_dict() -> Dict[str, Any]:
    return {
        "opacity": float(fishnet_opacity.value),
        "width": int(fishnet_width.value),
        "color_up": str(fishnet_color_up.value or "#00FF7F"),
        "color_dn": str(fishnet_color_dn.value or "#DC143C"),
    }

def _hashable(v: Any) -> Any:
    if isinstance(v, (int, float, bool, str, type(None))):
        return v
    if isinstance(v, (list, tuple)):
        return tuple(_hashable(x) for x in v)
    return str(v)


def _indicator_cache_key(ctx_sig: Tuple[Any, ...]) -> Tuple[Any, ...]:
    selected = tuple(sorted([str(x) for x in (ind_select.value or [])]))
    mp = int(ind_max_points.value or 0)

    params_parts = []
    for ind_id in selected:
        p = _ind_params_state.get(ind_id, {}) or {}
        params_parts.append((ind_id, tuple(sorted((k, _hashable(v)) for k, v in p.items()))))

    return ("ind_v1", ctx_sig, selected, tuple(params_parts), mp)


def _compute_indicator_bundle(df_show: pd.DataFrame, ctx_sig: Tuple[Any, ...]) -> indicators.IndicatorBundle:
    """Compute indicator traces/layout with caching.

    Caching is critical because trade-row selection triggers redraws frequently.
    """
    selected = [str(x) for x in (ind_select.value or [])]
    if not selected:
        return indicators.IndicatorBundle(traces=[], layout={}, warnings=[])

    key = _indicator_cache_key(ctx_sig)
    if key in _ind_cache:
        _diag("DIAG IND CACHE HIT", key=str(key), selected=selected, df_len=(0 if df_show is None else len(df_show)))
        return _ind_cache[key]

    params_by_id = {iid: dict(_ind_params_state.get(iid, {}) or {}) for iid in selected}
    t0 = time.time()
    bundle = indicators.compute_bundle(
        df_show=df_show,
        selected_ids=selected,
        params_by_id=params_by_id,
        max_points=int(ind_max_points.value or 8000),
    )
    if DIAG:
        t1 = time.time()
        shapes_n = None
        try:
            if isinstance(getattr(bundle, "layout", None), dict):
                shapes_n = len(bundle.layout.get("shapes", []) or [])
        except Exception:
            shapes_n = None
        _diag(
            "DIAG IND END",
            sec=round(t1 - t0, 3),
            traces=(len(bundle.traces) if getattr(bundle, "traces", None) is not None else None),
            shapes=shapes_n,
            warnings=getattr(bundle, "warnings", None),
        )

    _ind_cache[key] = bundle
    return bundle


def _labeled_widget_tip(title: str, widget: pn.viewable.Viewable, tip_text: str) -> pn.Column:
    title_md = pn.pane.Markdown(f"**{title}**", margin=(0, 0, 0, 0))
    tip_text = str(tip_text or "").strip()
    if tip_text:
        tip = pn.widgets.TooltipIcon(value=tip_text)
        head = pn.Row(title_md, pn.Spacer(), tip, sizing_mode="stretch_width", margin=(0, 0, 0, 0))
    else:
        head = pn.Row(title_md, pn.Spacer(), sizing_mode="stretch_width", margin=(0, 0, 0, 0))
    return pn.Column(head, widget, sizing_mode="stretch_width", margin=(0, 0, 4, 0))


def _make_ind_param_widget(ps: Any, *, current: Any) -> pn.widgets.Widget:
    kind = str(getattr(ps, "kind", "")).lower()
    if kind == "int":
        start = getattr(ps, "min", None)
        end = getattr(ps, "max", None)
        step = getattr(ps, "step", None)
        kwargs = {}
        if start is not None:
            kwargs["start"] = int(start)
        if end is not None:
            kwargs["end"] = int(end)
        if step is not None:
            kwargs["step"] = int(step)
        w = pn.widgets.IntInput(name="", value=int(current), **kwargs)
    elif kind == "float":
        start = getattr(ps, "min", None)
        end = getattr(ps, "max", None)
        step = getattr(ps, "step", None)
        kwargs = {}
        if start is not None:
            kwargs["start"] = float(start)
        if end is not None:
            kwargs["end"] = float(end)
        if step is not None:
            kwargs["step"] = float(step)
        w = pn.widgets.FloatInput(name="", value=float(current), **kwargs)
    elif kind == "bool":
        w = pn.widgets.Checkbox(name="", value=bool(current))
    elif kind == "select":
        w = pn.widgets.Select(name="", options=list(ps.options or []), value=current)
    else:
        w = pn.widgets.TextInput(name="", value=str(current))
    return w


def _rebuild_indicator_params_ui() -> None:
    """Rebuild parameter widgets for currently selected indicators.

    This does NOT trigger redraw.
    """
    selected = [str(x) for x in (ind_select.value or [])]
    objs = []

    for ind_id in selected:
        spec = indicators.get(ind_id)
        if spec is None:
            continue

        # defaults
        state = _ind_params_state.setdefault(ind_id, {})
        for p in spec.params:
            if p.key not in state:
                state[p.key] = p.default

        param_rows = []
        for p in spec.params:
            cur = state.get(p.key, p.default)
            w = _make_ind_param_widget(p, current=cur)

            def _mk_cb(_ind_id: str, _pkey: str):
                def _cb(evt):
                    _ind_params_state.setdefault(_ind_id, {})[_pkey] = evt.new
                    # invalidate cache (safe + simple)
                    _ind_cache.clear()
                return _cb

            try:
                w.param.watch(_mk_cb(ind_id, p.key), "value")
            except Exception:
                pass

            title = p.label_ru if lang.value == "RU" else p.label_en
            help_txt = p.help_ru if lang.value == "RU" else p.help_en
            param_rows.append(_labeled_widget_tip(title, w, help_txt))

        # Don't render an empty parameter card (keeps sidebar clean for "no-params" indicators)
        if not param_rows:
            continue

        card = pn.Card(
            *param_rows,
            collapsible=True,
            collapsed=False,
            title=(spec.title_ru if lang.value == "RU" else spec.title_en),
            margin=(0, 0, 6, 0),
        )
        objs.append(card)

    ind_params_panel.objects = objs


def _on_indicators_change(_event=None) -> None:
    # invalidate cache + rebuild params UI only
    _ind_cache.clear()
    _rebuild_indicator_params_ui()


def _clear_indicators(_event=None) -> None:
    try:
        ind_select.value = []
    except Exception:
        pass
    _ind_params_state.clear()
    _ind_cache.clear()
    ind_params_panel.objects = []




def _build_price_only_figure(df_show: pd.DataFrame) -> go.Figure:
    ctx = _last_price_ctx_sig if _last_price_ctx_sig is not None else _ctx_signature()
    bundle = _compute_indicator_bundle(df_show, ctx)

    _t0 = time.time()
    fig = plots.build_price_figure(
        df_show=df_show,
        res=None,
        chart_mode=str(chart_mode.value),
        max_points=int(max_points.value),
        hm_time_bins=int(hm_time_bins.value),
        hm_price_bins=int(hm_price_bins.value),
        is_py=False,
        show_flags={"show_trades": False, "show_entries": False, "show_exits": False, "show_uplevel": False, "show_dnlevel": False, "show_break": False},
        highlight_time=None,
        highlight_label=None,
        bt_from=None,
        bt_to=None,
        indicator_traces=bundle.traces,
        indicator_layout=bundle.layout,
        price_log=bool(getattr(price_log, "value", False)),
    )
    _diag_fig_stats("price_only", fig, sec=round(time.time() - _t0, 3), df_len=(0 if df_show is None else len(df_show)), chart_mode=str(chart_mode.value))
    return fig




def _build_figures(df_show: pd.DataFrame, res: Optional[backtest_runner.BacktestResult]) -> Tuple[go.Figure, go.Figure]:
    # Backtest window shown from last run (if exists)
    bt_from_used = None
    bt_to_used = None
    if _last_run is not None:
        bt_from_used = _last_run.get("bt_from")
        bt_to_used = _last_run.get("bt_to")

    ctx = _last_price_ctx_sig if _last_price_ctx_sig is not None else _ctx_signature()
    bundle = _compute_indicator_bundle(df_show, ctx)

    _t0p = time.time()
    price_fig = plots.build_price_figure(
        df_show=df_show,
        res=res,
        chart_mode=str(chart_mode.value),
        max_points=int(max_points.value),
        hm_time_bins=int(hm_time_bins.value),
        hm_price_bins=int(hm_price_bins.value),
        is_py=(strategy_lang.value == "Python"),
        show_flags=_show_flags_dict(),
        fishnet_style=_fishnet_style_dict(),
        highlight_time=_highlight_time,
        highlight_label=_highlight_label,
        bt_from=bt_from_used,
        bt_to=bt_to_used,
        show_bt_lines=True,
        show_bt_shade=True,
        indicator_traces=bundle.traces,
        indicator_layout=bundle.layout,
        price_log=bool(getattr(price_log, "value", False)),
    )
    _diag_fig_stats("price", price_fig, sec=round(time.time() - _t0p, 3), df_len=(0 if df_show is None else len(df_show)), has_res=(res is not None))

    _t0e = time.time()
    equity_fig = plots.build_equity_figure(
        res.equity if (res is not None) else pd.DataFrame(),
        highlight_time=_highlight_time,
        highlight_label=_highlight_label,
    )
    _diag_fig_stats("equity", equity_fig, sec=round(time.time() - _t0e, 3), df_len=(0 if df_show is None else len(df_show)), has_res=(res is not None))
    return price_fig, equity_fig


def _validate_and_clip_bt_window(df_show: pd.DataFrame, bt_from_text: str, bt_to_text: str) -> Tuple[pd.Timestamp, pd.Timestamp, int]:
    """
    Returns (dt_from_run, dt_to_run, bars_count) within df_show timestamp range.
    Raises ValueError with readable message on invalid window.
    """
    if not isinstance(df_show, pd.DataFrame) or len(df_show) == 0 or "timestamp" not in df_show.columns:
        raise ValueError("df_show пуст — нет данных для расчёта." if lang.value == "RU" else "df_show is empty — no data.")

    ts = pd.to_datetime(df_show["timestamp"], utc=True, errors="coerce")
    ts = ts.dropna().sort_values()
    if len(ts) < 2:
        raise ValueError("Слишком мало баров для расчёта." if lang.value == "RU" else "Not enough bars for backtest.")

    disp_min = ts.iloc[0]
    disp_max = ts.iloc[-1]

    raw_from = _parse_dt(bt_from_text)
    raw_to = _parse_dt(bt_to_text)

    dt_from = raw_from if raw_from is not None else disp_min
    dt_to = raw_to if raw_to is not None else disp_max

    # clip to display data bounds
    if dt_from < disp_min:
        dt_from = disp_min
    if dt_to > disp_max:
        dt_to = disp_max

    if dt_from >= dt_to:
        raise ValueError(
            "Окно бэктеста некорректно: 'С даты' должно быть меньше 'По дату'."
            if lang.value == "RU"
            else "Invalid backtest window: 'From' must be less than 'To'."
        )

    mask = (ts >= dt_from) & (ts <= dt_to)
    bars = int(mask.sum())
    if bars < 2:
        raise ValueError(
            "В выбранном окне бэктеста меньше 2 баров. Расширьте окно или смените TF."
            if lang.value == "RU"
            else "Less than 2 bars in selected backtest window. Expand window or change TF."
        )

    return dt_from, dt_to, bars


def _run_backtest(event=None) -> None:
    """Background backtest: compute in worker thread, update UI via next_tick."""
    global _job_seq, _job_running

    with _job_lock:
        _job_seq += 1
        job_id = _job_seq
        _job_running = True

    busy_tok = _busy_begin("Считаю в фоне..." if lang.value == "RU" else "Computing in background...")

    # snapshot UI params
    ui = {
        "ctx_sig": _ctx_signature(),
        "tf": tf.value,
        "warmup_bars": int(warmup_bars.value),
        "strategy_lang": str(strategy_lang.value),
        "yaml_text": yaml_text.value,
        "strategies_dir": strategies_dir.value,
        "py_select": py_select.value,
        "bt_from_text": (bt_from.value or "").strip(),
        "bt_to_text": (bt_to.value or "").strip(),
        "overrides": {
            "needlong": bool(allow_long.value),
            "needshort": bool(allow_short.value),
            "allow_long": bool(allow_long.value),
            "allow_short": bool(allow_short.value),
            "revers": bool(reverse_logic.value),
            "length": int(ov_length.value),
            "extreme": int(ov_extreme.value),
            "Extreme": int(ov_extreme.value),
            "corr": float(ov_corr.value),
            "leftBars": int(pop_left_bars.value),
            "rightBars": int(pop_right_bars.value),
            "atr_length": int(pop_atr_length.value),
            "atr_mult": float(pop_atr_mult.value),
            "min_tick": float(pop_min_tick.value),
            "real_pop_trade": bool(pop_real_trade.value),
            "pop_exec_model": str(pop_exec_model.value),
            "fishnet_filter": bool(fishnet_filter.value),
            "fishnet_tf": str(fishnet_tf.value),
            "fishnet_start_len": int(fishnet_start_len.value),
            "fishnet_step": int(fishnet_step.value),
            "fishnet_count": int(fishnet_count.value),
            "fishnet_show": bool(fishnet_show.value),
            "fee_pct": float(fee_pct.value),
            "slippage_bps": float(slippage_bps.value),
            "sl_pct": float(sl_pct.value),
            "tp_pct": float(tp_pct.value),
            "intrabar_priority": str(intrabar.value),
            "no_reinvest": bool(no_reinvest.value),
            "pine_text": pine_text.value,
        },
        "initial_capital": float(initial_capital.value or 0.0),
    }

    def _job() -> Dict[str, Any]:
        df_warm, df_show, data_sig = _get_data()

        # validate/clip backtest window INSIDE current display data
        dt_from_run, dt_to_run, bars = _validate_and_clip_bt_window(df_show, ui["bt_from_text"], ui["bt_to_text"])

        trimmed = backtest_runner.run_backtest(
            df_warm=df_warm,
            data_sig=data_sig,
            timeframe=ui["tf"],
            dt_from_run=dt_from_run,
            dt_to_run=dt_to_run,
            warmup_bars=ui["warmup_bars"],
            strategy_lang=ui["strategy_lang"],
            yaml_text=ui["yaml_text"],
            strategies_dir=ui["strategies_dir"],
            py_select_value=ui["py_select"],
            overrides=ui["overrides"],
            pine_text=ui["overrides"]["pine_text"],
            bt_cache=_bt_cache,
        )

        # Initial/Final balance (UI layer)
        ic = float(ui["initial_capital"])
        fe = float(trimmed.metrics.get("Final Equity", 1.0) if trimmed.metrics else 1.0)
        trimmed.metrics = dict(trimmed.metrics or {})
        trimmed.metrics["Initial Capital (USD)"] = ic
        trimmed.metrics["Final Balance (USD)"] = ic * fe
        trimmed.metrics["BT Bars"] = bars

        trades_events_df = _make_trades_events(trimmed.trades)
        eq_df = trimmed.equity if isinstance(trimmed.equity, pd.DataFrame) else pd.DataFrame()

        return {
            "job_id": job_id,
            "ctx_sig": ui["ctx_sig"],
            "strategy_lang": ui["strategy_lang"],
            "dt_from": dt_from_run,
            "dt_to": dt_to_run,
            "df_show": df_show,
            "res": trimmed,
            "trades_events": trades_events_df,
            "equity_df": eq_df,
            "bt_from_used": dt_from_run,
            "bt_to_used": dt_to_run,
        }

    def _on_done(result: Dict[str, Any]) -> None:
        global _job_running
        with _job_lock:
            if result.get("job_id") != _job_seq:
                _busy_end(busy_tok)
                return
            _job_running = False

        def _apply():
            global _last_run, _last_trades_events_df
            global _last_df_show, _last_ctx_sig, _last_price_ctx_sig
            global _highlight_time, _highlight_label, _picked_row_id, _last_picked_set

            try:
                # persist backtest range memory (per strategy)
                _save_bt_range_for_current_strategy()

                # cache df_show for redraw (can be reused for price)
                _last_df_show = result["df_show"]
                _last_ctx_sig = result["ctx_sig"]
                _last_price_ctx_sig = result["ctx_sig"]

                res = result["res"]
                _last_run = {
                    "res": res,
                    "dt_from": result["dt_from"],
                    "dt_to": result["dt_to"],
                    "strategy_lang": result["strategy_lang"],
                    "ctx_sig": result["ctx_sig"],
                    "bt_from": result["bt_from_used"],
                    "bt_to": result["bt_to_used"],
                }

                _last_trades_events_df = result["trades_events"]
                _diag("DIAG TRADES DF", rows=(0 if _last_trades_events_df is None else len(_last_trades_events_df)), cols=(list(_last_trades_events_df.columns) if _last_trades_events_df is not None else None))
                _set_trades_table_df(_last_trades_events_df)

                equity_table.value = result["equity_df"]

                # reset highlight on new run
                _highlight_time = None
                _highlight_label = None

                price_fig, equity_fig = _build_figures(_last_df_show, res)

                _t0a = time.time()
                price_plot.object = price_fig
                _diag_throttle("DIAG UI ASSIGN price_plot", every_sec=0.5, sec=round(time.time() - _t0a, 4), traces=(len(price_fig.data) if getattr(price_fig, "data", None) is not None else None))

                _t0b = time.time()
                equity_plot.object = equity_fig
                _diag_throttle("DIAG UI ASSIGN equity_plot", every_sec=0.5, sec=round(time.time() - _t0b, 4), traces=(len(equity_fig.data) if getattr(equity_fig, "data", None) is not None else None))

                _render_metrics_block(res.metrics or {})
                _set_status(tr("done"), "success")
            except Exception as e:
                _set_status(f"Ошибка: {e}" if lang.value == "RU" else f"Error: {e}", "danger")
            finally:
                _busy_end(busy_tok)

        _ui_call(_apply)

    def _on_err(exc: Exception) -> None:
        global _job_running
        with _job_lock:
            if job_id != _job_seq:
                _busy_end(busy_tok)
                return
            _job_running = False

        def _apply():
            _set_status(f"Ошибка: {exc}" if lang.value == "RU" else f"Error: {exc}", "danger")
            _busy_end(busy_tok)
        _ui_call(_apply)

    fut = _EXEC.submit(_job)

    def _cb(f):
        try:
            r = f.result()
            _on_done(r)
        except Exception as e:
            _on_err(e)

    fut.add_done_callback(_cb)


def _redraw_only(event=None) -> None:
    """
    Redraw behavior:
      A) If PRICE context unchanged -> redraw from cached df_show (NO CSV reads).
      B) If PRICE context changed -> read new df_show in background and redraw price for NEW range,
         but KEEP last strategy overlay (res) so it does NOT disappear.
    """
    global _last_df_show, _last_price_ctx_sig

    with _job_lock:
        if _job_running:
            _set_status(
                "Считаю в фоне — дождитесь завершения." if lang.value == "RU"
                else "Background compute is running — please wait.",
                "warning",
            )
            return

    current_sig = _ctx_signature()
    res = _last_run["res"] if _last_run is not None else None
    backtest_sig = _last_run.get("ctx_sig") if _last_run is not None else None

    # FAST PATH
    if _last_df_show is not None and _last_price_ctx_sig is not None and current_sig == _last_price_ctx_sig:
        try:
            price_fig, equity_fig = _build_figures(_last_df_show, res)
            price_plot.object = price_fig
            equity_plot.object = equity_fig
            _render_metrics_block(res.metrics or {} if res is not None else {})

            if res is not None and backtest_sig is not None and current_sig != backtest_sig:
                _set_status(
                    "Цена перерисована. Стратегия/Equity — от предыдущего Run Backtest."
                    if lang.value == "RU"
                    else "Price redrawn. Strategy/Equity are from previous Run Backtest.",
                    "warning",
                )
            else:
                _set_status("График перерисован." if lang.value == "RU" else "Chart redrawn.", "success")
        except Exception as e:
            _set_status(f"Ошибка перерисовки: {e}" if lang.value == "RU" else f"Redraw error: {e}", "danger")
        return

    # SLOW PATH
    want_sig = current_sig
    busy_tok = _busy_begin("Перерисовываю BTC по новому диапазону..." if lang.value == "RU" else "Redrawing BTC for new range...")

    def _job() -> pd.DataFrame:
        _, df_show_new, _ = _get_data()
        return df_show_new

    def _apply_df(df_show_new: pd.DataFrame) -> None:
        global _last_df_show, _last_price_ctx_sig
        try:
            if _ctx_signature() != want_sig:
                return

            _last_df_show = df_show_new
            _last_price_ctx_sig = want_sig

            if not isinstance(df_show_new, pd.DataFrame) or len(df_show_new) == 0:
                price_plot.object = go.Figure()
                _set_status(
                    "Пустой график: по выбранному диапазону/TF нет данных (df_show пуст)."
                    if lang.value == "RU"
                    else "Empty chart: no data for selected range/TF (df_show is empty).",
                    "warning",
                )
                return

            # Build price for NEW df_show; keep overlay if res exists
            if res is None:
                price_plot.object = _build_price_only_figure(df_show_new)
                equity_plot.object = go.Figure()
                _render_metrics_block({})
                _set_status(
                    "Перерисовано: только BTC (без стратегии)." if lang.value == "RU" else "Redrawn: BTC only (no strategy).",
                    "success",
                )
                return

            _t0p = time.time()
            _figp = plots.build_price_figure(
                df_show=df_show_new,
                res=res,
                chart_mode=str(chart_mode.value),
                max_points=int(max_points.value),
                hm_time_bins=int(hm_time_bins.value),
                hm_price_bins=int(hm_price_bins.value),
                is_py=(strategy_lang.value == "Python"),
                show_flags=_show_flags_dict(),
        fishnet_style=_fishnet_style_dict(),
                highlight_time=_highlight_time,
                highlight_label=_highlight_label,
                bt_from=_last_run.get("bt_from") if _last_run else None,
                bt_to=_last_run.get("bt_to") if _last_run else None,
                show_bt_lines=True,
                show_bt_shade=True,
            )
            _diag_fig_stats("price_direct", _figp, sec=round(time.time() - _t0p, 3), df_len=(0 if df_show_new is None else len(df_show_new)))
            _t0a = time.time()
            price_plot.object = _figp
            _diag_throttle("DIAG UI ASSIGN price_plot", every_sec=0.5, sec=round(time.time() - _t0a, 4), traces=(len(_figp.data) if getattr(_figp, "data", None) is not None else None))

            _t0e = time.time()
            _fige = plots.build_equity_figure(
                res.equity,
                highlight_time=_highlight_time,
                highlight_label=_highlight_label,
            )
            _render_metrics_block(res.metrics or {})

            if backtest_sig is not None and want_sig != backtest_sig:
                _set_status(
                    "Цена обновлена по новому диапазону. Стратегия/Equity — от последнего Run Backtest (для нового диапазона нужен новый Run Backtest)."
                    if lang.value == "RU"
                    else "Price updated for new range. Strategy/Equity are from last Run Backtest (run again for the new range).",
                    "warning",
                )
            else:
                _set_status("График перерисован." if lang.value == "RU" else "Chart redrawn.", "success")

        except Exception as e:
            _set_status(f"Ошибка перерисовки: {e}" if lang.value == "RU" else f"Redraw error: {e}", "danger")
        finally:
            _busy_end(busy_tok)

    def _cb(fut):
        try:
            df_show_new = fut.result()
            _ui_call(lambda: _apply_df(df_show_new))
        except Exception as e:
            _ui_call(lambda: (
                _set_status(f"Ошибка перерисовки: {e}" if lang.value == "RU" else f"Redraw error: {e}", "danger"),
                _busy_end(busy_tok),
            ))

    fut = _EXEC.submit(_job)
    fut.add_done_callback(_cb)




# --- On-chain master actions (run in background to avoid WebSocket timeouts) ---
_onchain_job_id = 0

def _onchain_reload_indicators(event=None) -> None:
    """Fast: clear indicator caches and redraw from already-built files."""
    try:
        aws_network.clear_cache()
    except Exception:
        pass
    try:
        onchain_status.object = f"✅ {ui_i18n.I18N['onchain_status'][lang.value]}: reloaded"
    except Exception:
        onchain_status.object = "✅ on-chain: reloaded"

def _onchain_update_indicators(event=None) -> None:
    """Heavy: recompute last N days and export per-indicator datasets."""
    global _onchain_job_id

    if not bool(ONCHAIN_MASTER_ENABLED):
        onchain_status.object = "on-chain master disabled (set MYBOT_ONCHAIN_AUTO=1)"
        return

    wd_raw = getattr(onchain_window_days, "value", 31)
    wd = 31 if wd_raw is None else int(wd_raw)

    # UI pre-state
    try:
        onchain_update_btn.disabled = True
        onchain_reload_btn.disabled = True
    except Exception:
        pass
    wd_label = "ALL" if wd == 0 else f"{wd}d"
    onchain_status.object = f"⏳ {ui_i18n.I18N['onchain_status'][lang.value]}: updating (window={wd_label}) ..."

    def _job():
        # heavy work: NO UI touches here
        res = aws_indicator_pipeline.update_network_daily(window_days=wd)
        return res

    def _done(job_id: int, res, err):
        global _onchain_job_id
        _onchain_job_id = job_id

        try:
            onchain_update_btn.disabled = False
            onchain_reload_btn.disabled = False
        except Exception:
            pass

        if err is not None:
            onchain_status.object = f"❌ {ui_i18n.I18N['onchain_status'][lang.value]}: {err!r}"
            return

        try:
            aws_network.clear_cache()
        except Exception:
            pass

        try:
            onchain_status.object = (
                f"✅ {ui_i18n.I18N['onchain_status'][lang.value]}: "
                f"recomputed {res.days_recomputed} days, [{res.min_day} → {res.max_day}]"
            )
        except Exception:
            onchain_status.object = "✅ on-chain: updated"

    _onchain_job_id = bg_jobs.submit(_job, _done)
def _clean_chart(event=None) -> None:
    """
    Build price-only chart for current range/TF from scratch (reads data),
    and clears strategy artifacts. After that, Run Backtest overlays normally.
    """
    global _last_run, _last_trades_events_df, _last_ctx_sig
    global _last_df_show, _last_price_ctx_sig
    global _highlight_time, _highlight_label, _picked_row_id, _last_picked_set, _pick_update_guard

    with _job_lock:
        if _job_running:
            _set_status(
                "Считаю в фоне — дождитесь завершения." if lang.value == "RU"
                else "Background compute is running — please wait.",
                "warning",
            )
            return

    want_sig = _ctx_signature()
    busy_tok = _busy_begin("Строю чистый график..." if lang.value == "RU" else "Building clean chart...")

    def _job() -> pd.DataFrame:
        _, df_show_new, _ = _get_data()
        return df_show_new

    def _apply_df(df_show_new: pd.DataFrame) -> None:
        global _last_run, _last_trades_events_df, _last_ctx_sig
        global _last_df_show, _last_price_ctx_sig
        global _highlight_time, _highlight_label, _picked_row_id, _last_picked_set, _pick_update_guard

        try:
            if _ctx_signature() != want_sig:
                return

            _last_df_show = df_show_new
            _last_price_ctx_sig = want_sig

            # Clear strategy state
            _last_run = None
            _last_ctx_sig = None
            _last_trades_events_df = None

            _highlight_time = None
            _highlight_label = None
            _picked_row_id = None
            _last_picked_set = set()
            _pick_update_guard = False

            _set_trades_table_df(None)
            equity_table.value = pd.DataFrame()
            equity_plot.object = go.Figure()
            _render_metrics_block({})

            if not isinstance(df_show_new, pd.DataFrame) or len(df_show_new) == 0:
                price_plot.object = go.Figure()
                _set_status(
                    "Пустой график: по выбранному диапазону/TF нет данных."
                    if lang.value == "RU"
                    else "Empty chart: no data for selected range/TF.",
                    "warning",
                )
                return

            price_plot.object = _build_price_only_figure(df_show_new)

            # UX: optionally auto-fill backtest window from display range (nice default)
            bt_from.value = (date_from.value or "").strip()
            bt_to.value = (date_to.value or "").strip()

            _set_status(
                "Чистый график построен. Теперь можно запускать Run Backtest — результаты наложатся сверху."
                if lang.value == "RU"
                else "Clean chart built. Now run Backtest — results will overlay on top.",
                "success",
            )

        except Exception as e:
            _set_status(f"Ошибка: {e}" if lang.value == "RU" else f"Error: {e}", "danger")
        finally:
            _busy_end(busy_tok)

    def _cb(fut):
        try:
            df_show_new = fut.result()
            _ui_call(lambda: _apply_df(df_show_new))
        except Exception as e:
            _ui_call(lambda: (
                _set_status(f"Ошибка: {e}" if lang.value == "RU" else f"Error: {e}", "danger"),
                _busy_end(busy_tok),
            ))

    fut = _EXEC.submit(_job)
    fut.add_done_callback(_cb)


def _on_trade_pick(event=None) -> None:
    global _highlight_time, _highlight_label, _picked_row_id, _last_picked_set, _pick_update_guard
    if _pick_update_guard:
        return
    try:
        df = trades_table.value
        if not isinstance(df, pd.DataFrame) or len(df) == 0 or "pick" not in df.columns:
            _picked_row_id = None
            _last_picked_set = set()
            _highlight_time = None
            _highlight_label = None
            _redraw_only(None)
            return

        picked_ids = set(int(x) for x in df.loc[df["pick"] == True, "row_id"].tolist())
        if not picked_ids:
            _picked_row_id = None
            _last_picked_set = set()
            _highlight_time = None
            _highlight_label = None
            _redraw_only(None)
            return

        newly = picked_ids - (_last_picked_set or set())
        if newly:
            chosen = sorted(newly)[-1]
        elif _picked_row_id in picked_ids:
            chosen = int(_picked_row_id)
        else:
            chosen = sorted(picked_ids)[0]

        _picked_row_id = int(chosen)
        _last_picked_set = set([_picked_row_id])

        if len(picked_ids) > 1:
            df2 = df.copy()
            df2["pick"] = df2["row_id"].astype(int).eq(_picked_row_id)
            _pick_update_guard = True
            trades_table.value = df2
            _pick_update_guard = False
            df = df2

        row = df.loc[df["row_id"].astype(int) == _picked_row_id].head(1)
        if len(row) == 0:
            _highlight_time = None
            _highlight_label = None
        else:
            r = row.iloc[0]
            t = pd.to_datetime(r.get("time"), utc=True, errors="coerce")
            if pd.isna(t):
                _highlight_time = None
                _highlight_label = None
            else:
                _highlight_time = t
                _highlight_label = str(r.get("side_label_raw", "") or "CLOSE").upper()

        _redraw_only(None)
    except Exception:
        pass


# --- Containers for python-only UI blocks ---
py_mode_block: Optional[pn.Column] = None
py_risk_container: Optional[pn.Column] = None
py_pine_container: Optional[pn.Column] = None

# Sidebar collapsible sections
sidebar_display_card: Optional[pn.Card] = None
sidebar_indicators_card: Optional[pn.Card] = None
sidebar_strategy_card: Optional[pn.Card] = None
equity_curve_card: Optional[pn.Card] = None


def _sync_visibility(*events) -> None:
    is_disk = data_source.value == tr("disk")
    data_dir.visible = is_disk
    csv_select.visible = is_disk
    upload.visible = not is_disk

    is_py = strategy_lang.value == "Python"

    sel_py = str(py_select.value or "")
    is_zz2 = is_py and sel_py == "pine_v5_zz2.py"
    is_pop = is_py and sel_py == "pop_reversal.py"

    py_select.visible = is_py
    yaml_text.visible = not is_py

    if py_mode_block is not None:
        py_mode_block.visible = is_py
    if py_risk_container is not None:
        py_risk_container.visible = is_py
    if py_pine_container is not None:
        py_pine_container.visible = is_py

    allow_long.visible = is_py
    allow_short.visible = is_py
    reverse_logic.visible = is_zz2
    ov_length.visible = is_zz2
    ov_extreme.visible = is_zz2
    ov_corr.visible = is_zz2
    pop_left_bars.visible = is_pop
    pop_right_bars.visible = is_pop
    pop_atr_length.visible = is_pop
    pop_atr_mult.visible = is_pop
    pop_min_tick.visible = is_pop
    pop_real_trade.visible = is_pop
    pop_exec_model.visible = is_pop
    fishnet_filter.visible = is_pop
    fishnet_tf.visible = is_pop
    fishnet_start_len.visible = is_pop
    fishnet_step.visible = is_pop
    fishnet_count.visible = is_pop
    fishnet_show.visible = is_pop
    fishnet_opacity.visible = is_pop and bool(fishnet_show.value)
    fishnet_width.visible = is_pop and bool(fishnet_show.value)
    fishnet_color_up.visible = is_pop and bool(fishnet_show.value)
    fishnet_color_dn.visible = is_pop and bool(fishnet_show.value)
    pine_text.visible = is_py

    show_uplevel.visible = is_zz2
    show_dnlevel.visible = is_zz2
    show_break.visible = is_zz2
    show_pop_pivots.visible = is_pop
    show_pop_levels.visible = is_pop

    if not is_py:
        show_uplevel.value = False
        show_dnlevel.value = False
        show_break.value = False
        show_uplevel.disabled = True
        show_dnlevel.disabled = True
        show_break.disabled = True
        show_pop_pivots.value = False
        show_pop_levels.value = False
        fishnet_show.value = False
        show_pop_pivots.disabled = True
        show_pop_levels.disabled = True

        if _last_run is not None and str(_last_run.get("strategy_lang")) != "YAML":
            _clear_view(
                "Переключено на YAML. Запустите YAML-бэктест."
                if lang.value == "RU"
                else "Switched to YAML. Run YAML backtest."
            )
    else:
        show_uplevel.disabled = False
        show_dnlevel.disabled = False
        show_break.disabled = False
        show_pop_pivots.disabled = False
        show_pop_levels.disabled = False
        if not is_zz2:
            show_uplevel.value = False
            show_dnlevel.value = False
            show_break.value = False
            show_uplevel.disabled = True
            show_dnlevel.disabled = True
            show_break.disabled = True
        else:
            show_uplevel.disabled = False
            show_dnlevel.disabled = False
            show_break.disabled = False

        if not is_pop:
            show_pop_pivots.value = False
            show_pop_levels.value = False
            show_pop_pivots.disabled = True
            show_pop_levels.disabled = True
        else:
            show_pop_pivots.disabled = False
            show_pop_levels.disabled = False

        if _last_run is not None and str(_last_run.get("strategy_lang")) != "Python":
            _clear_view(
                "Переключено на Python. Запустите Python-бэктест."
                if lang.value == "RU"
                else "Switched to Python. Run Python backtest."
            )


def _build_risk_block() -> pn.Column:
    return pn.Column(
        ui_i18n.make_section_pane(lang, "risk", level=3),
        ui_i18n.labeled_widget(tr("initial_cap"), initial_capital, lang_widget=lang, help_key="initial_cap"),
        ui_i18n.labeled_widget(tr("no_reinvest"), no_reinvest, lang_widget=lang, help_key="no_reinvest"),
        ui_i18n.labeled_widget("fee_pct", fee_pct, lang_widget=lang, help_key="fee_pct"),
        ui_i18n.labeled_widget("slippage_bps", slippage_bps, lang_widget=lang, help_key="slippage_bps"),
        ui_i18n.labeled_widget("sl_pct", sl_pct, lang_widget=lang, help_key="sl_pct"),
        ui_i18n.labeled_widget("tp_pct", tp_pct, lang_widget=lang, help_key="tp_pct"),
        ui_i18n.labeled_widget("intrabar_priority", intrabar, lang_widget=lang, help_key="intrabar"),
        sizing_mode="stretch_width",
        margin=(0, 0, 0, 0),
    )

def _relabel_ui(*events) -> None:
    _sync_lang_buttons()

    data_source.name = tr("src")
    data_source.options = [tr("disk"), tr("upload")]
    if data_source.value not in data_source.options:
        data_source.value = tr("disk")

    data_dir.name = tr("data_dir")
    csv_select.name = tr("csv")
    upload.name = tr("upload")

    symbol.name = tr("symbol")
    tf.name = tr("tf")

    date_from.name = tr("date_from")
    date_to.name = tr("date_to")
    warmup_bars.name = tr("warmup")

    # Indicators
    ind_select.name = tr("ind_select")
    ind_max_points.name = tr("ind_max_points")

    # on-chain master tools
    try:
        onchain_window_days.name = tr("onchain_window_days")
        onchain_update_btn.name = tr("onchain_update")
        onchain_reload_btn.name = tr("onchain_reload")
        onchain_card.title = ui_i18n.I18N["onchain_tools"][lang.value]
    except Exception:
        pass
    ind_clear_btn.name = tr("ind_clear")
    ind_note.object = (
        "<span style='color:#9aa0a6; font-size:12px'>Комментарий: изменения индикаторов применяются по кнопке «Перерисовать график».</span>"
        if lang.value == "RU"
        else "<span style='color:#9aa0a6; font-size:12px'>Note: indicator changes apply when you click 'Redraw chart'.</span>"
    )
    try:
        ind_select.options = indicators.option_map(lang.value)
    except Exception:
        ind_select.options = {}
    _rebuild_indicator_params_ui()

    chart_mode.name = tr("chart_mode")
    max_points.name = tr("max_points")
    hm_time_bins.name = tr("hm_tb")
    hm_price_bins.name = tr("hm_pb")

    strategy_lang.name = tr("strat_lang")
    strategies_dir.name = tr("strat_dir")
    py_select.name = tr("py_strat")
    yaml_text.name = tr("yaml_strat")

    allow_long.name = tr("allow_long")
    allow_short.name = tr("allow_short")
    reverse_logic.name = tr("reverse")

    ov_length.name = tr("length")
    ov_extreme.name = tr("extreme")
    ov_corr.name = tr("corr")

    pop_left_bars.name = tr("pop_left_bars")
    pop_right_bars.name = tr("pop_right_bars")
    pop_atr_length.name = tr("pop_atr_length")
    pop_atr_mult.name = tr("pop_atr_mult")
    pop_min_tick.name = tr("pop_min_tick")
    pop_real_trade.name = tr("pop_real_trade")
    pop_exec_model.name = tr("exec_model")
    pop_exec_model.options = {
        "deterministic": tr("exec_det"),
        "conservative": tr("exec_cons"),
    }
    fishnet_filter.name = tr("fishnet_filter")
    fishnet_tf.name = tr("fishnet_tf")
    fishnet_start_len.name = tr("fishnet_start_len")
    fishnet_step.name = tr("fishnet_step")
    fishnet_count.name = tr("fishnet_count")
    fishnet_show.name = tr("fishnet_show")
    fishnet_opacity.name = tr("fishnet_opacity")
    fishnet_width.name = tr("fishnet_width")
    fishnet_color_up.name = tr("fishnet_color_up")
    fishnet_color_dn.name = tr("fishnet_color_dn")

    show_trades.name = tr("show_trades")
    show_entries.name = tr("show_entries")
    show_exits.name = tr("show_exits")
    show_uplevel.name = tr("show_uplevel")
    show_dnlevel.name = tr("show_dnlevel")
    show_break.name = tr("show_break")

    show_pop_pivots.name = tr("show_pop_pivots")
    show_pop_levels.name = tr("show_pop_levels")

    run_btn.name = tr("run")
    redraw_btn.name = tr("redraw")

    clean_btn.name = "Создать чистый график" if lang.value == "RU" else "Create clean chart"
    clear_overlays_btn.name = "Очистить оверлеи стратегии" if lang.value == "RU" else "Clear strategy overlays"
    bt_use_display_btn.name = "Взять из диапазона графика" if lang.value == "RU" else "Use display range"

    bt_from.name = "С даты (окно бэктеста)" if lang.value == "RU" else "Backtest from"
    bt_to.name = "По дату (окно бэктеста)" if lang.value == "RU" else "Backtest to"
    bt_note.object = (
        "💡 Пусто = использовать диапазон графика. Окно бэктеста подсвечивается на графике BTC."
        if lang.value == "RU"
        else "💡 Empty = use display range. Backtest window is highlighted on the BTC chart."
    )

    metrics_trades_card.title = ui_i18n.I18N["metrics_trades"][lang.value]
    equity_table_card.title = ui_i18n.I18N["equity_table"][lang.value]

    if sidebar_display_card is not None:
        sidebar_display_card.title = ui_i18n.I18N["display"][lang.value]
    if sidebar_indicators_card is not None:
        sidebar_indicators_card.title = ui_i18n.I18N["indicators"][lang.value]
    if sidebar_strategy_card is not None:
        sidebar_strategy_card.title = ui_i18n.I18N["strategy"][lang.value]
    if equity_curve_card is not None:
        equity_curve_card.title = ui_i18n.I18N["equity_curve"][lang.value]

    try:
        trades_table.titles = ui_i18n.trades_titles(lang.value)
    except Exception:
        pass

    if _last_run is not None:
        _render_metrics_block(_last_run["res"].metrics or {})
    else:
        _render_metrics_block({})

    risk_block.objects = _build_risk_block().objects
    _sync_visibility()

# ---------------- watchers + init (deferred) ----------------
_watchers_attached = False

def _attach_watchers_and_init():
    """Attach param/watch callbacks and run lightweight init once per session.
    Deferring to pn.state.onload avoids edge-cases where the document/session
    is not fully ready yet (and prevents NameError on partial imports).
    """
    global _watchers_attached
    if _watchers_attached:
        return
    _watchers_attached = True

    def _safe_watch(obj, cb, attr="value", name="<widget>"):
        if obj is None:
            LOG.error("Watcher skipped: %s is None", name)
            return
        try:
            obj.param.watch(cb, attr)
        except Exception:
            LOG.exception("Failed to attach watcher for %s.%s", name, attr)

    def _safe_click(btn, cb, name="<button>"):
        if btn is None:
            LOG.error("on_click skipped: %s is None", name)
            return
        try:
            btn.on_click(cb)
        except Exception:
            LOG.exception("Failed to attach on_click for %s", name)

    # watchers
    _safe_watch(globals().get("data_dir"), lambda e: _refresh_csv_list(), name="data_dir")
    _safe_watch(globals().get("strategies_dir"), lambda e: _refresh_py_list(), name="strategies_dir")
    _safe_watch(globals().get("data_source"), _sync_visibility, name="data_source")
    _safe_watch(globals().get("strategy_lang"), lambda e: (_load_bt_range_for_current_strategy(), _sync_visibility()), name="strategy_lang")
    _safe_watch(globals().get("py_select"), lambda e: (_load_bt_range_for_current_strategy(), _load_pine_defaults(), _sync_visibility()), name="py_select")

    _safe_watch(globals().get("symbol"), _on_symbol_change, name="symbol")
    _safe_watch(globals().get("tf"), _on_tf_change, name="tf")
    _safe_watch(globals().get("price_log"), _apply_price_axis_scale, name="price_log")
    _safe_watch(globals().get("lang"), _relabel_ui, name="lang")
    _safe_watch(globals().get("trades_table"), _on_trade_pick, name="trades_table")

    _safe_watch(globals().get("ind_select"), _on_indicators_change, name="ind_select")
    _safe_watch(globals().get("ind_max_points"), lambda e: _ind_cache.clear(), name="ind_max_points")
    _safe_click(globals().get("ind_clear_btn"), _clear_indicators, name="ind_clear_btn")

    _safe_click(globals().get("run_btn"), _run_backtest, name="run_btn")
    _safe_click(globals().get("redraw_btn"), _redraw_only, name="redraw_btn")
    _safe_click(globals().get("onchain_update_btn"), _onchain_update_indicators, name="onchain_update_btn")
    _safe_click(globals().get("onchain_reload_btn"), _onchain_reload_indicators, name="onchain_reload_btn")
    _safe_click(globals().get("clean_btn"), _clean_chart, name="clean_btn")
    _safe_click(globals().get("bt_use_display_btn"), _use_display_range_for_bt, name="bt_use_display_btn")
    _safe_click(globals().get("clear_overlays_btn"), _clear_strategy_overlays, name="clear_overlays_btn")

    # init
    try:
        # Apply preset for default symbol (if /opt dirs exist) before refreshing CSV list
        _apply_symbol_preset(str(symbol.value or ""))
        _refresh_csv_list()
        _refresh_py_list()
        _load_pine_defaults()
        _on_tf_change(None)
        _render_metrics_block({})
        _sync_lang_buttons()
        _load_bt_range_for_current_strategy()
    except Exception:
        LOG.exception("Init failed")


def _on_session_loaded():
    LOG.debug("pn.state.onload: attaching watchers/init")
    _attach_watchers_and_init()
    # heartbeat for WS status (best-effort)
    try:
        _ws_tick()
        pn.state.add_periodic_callback(_ws_tick, period=2000, start=True)
    except Exception:
        pass

pn.state.onload(_on_session_loaded)

# ---------------- Layout ----------------
h_data = ui_i18n.make_section_pane(lang, "data", level=3)
h_range = ui_i18n.make_section_pane(lang, "range", level=3)
h_mode = ui_i18n.make_section_pane(lang, "mode", level=3)
h_pine = ui_i18n.make_section_pane(lang, "pine_inputs", level=3)

warmup_help = ui_i18n.make_note_pane(lang, "warmup_help")
hm_time_help = ui_i18n.make_note_pane(lang, "hm_tb_help")
hm_price_help = ui_i18n.make_note_pane(lang, "hm_pb_help")

risk_block = _build_risk_block()

py_mode_block = pn.Column(
    pn.layout.Divider(margin=(6, 0, 6, 0)),
    h_mode,
    allow_long,
    allow_short,
    reverse_logic,
    ov_length,
    ov_extreme,
    ov_corr,
    pop_left_bars,
    pop_right_bars,
    pop_atr_length,
    pop_atr_mult,
    pop_min_tick,
    pop_real_trade,
    pop_exec_model,
    fishnet_filter,
    fishnet_tf,
    fishnet_start_len,
    fishnet_step,
    fishnet_count,
    fishnet_show,
    fishnet_opacity,
    fishnet_width,
    fishnet_color_up,
    fishnet_color_dn,
    sizing_mode="stretch_width",
    margin=(0, 0, 0, 0),
)

py_risk_container = pn.Column(
    pn.layout.Divider(margin=(6, 0, 6, 0)),
    risk_block,
    sizing_mode="stretch_width",
    margin=(0, 0, 0, 0),
)

py_pine_container = pn.Column(
    pn.layout.Divider(margin=(6, 0, 6, 0)),
    h_pine,
    pine_text,
    sizing_mode="stretch_width",
    margin=(0, 0, 0, 0),
)

sidebar_display_card = pn.Card(
    chart_mode,
    max_points,
    hm_time_bins,
    hm_time_help,
    hm_price_bins,
    hm_price_help,
    collapsible=True,
    collapsed=False,
    title=ui_i18n.I18N["display"][lang.value],
    margin=(0, 0, 6, 0),
)

# backtest window block (above run)
bt_window_block = pn.Column(
    pn.pane.Markdown("### Окно бэктеста" if lang.value == "RU" else "### Backtest window", margin=(0, 0, 6, 0)),
    bt_from,
    bt_to,
    bt_note,
    pn.Row(bt_use_display_btn, clear_overlays_btn, sizing_mode="stretch_width"),
    sizing_mode="stretch_width",
    margin=(0, 0, 0, 0),
)

sidebar_strategy_card = pn.Card(
    strategy_lang,
    strategies_dir,
    py_select,
    yaml_text,
    bt_window_block,
    py_mode_block,
    py_risk_container,
    py_pine_container,
    run_btn,
    collapsible=True,
    collapsed=True,
    title=ui_i18n.I18N["strategy"][lang.value],
    margin=(0, 0, 6, 0),
)

# Range buttons: Redraw + Clean under "Диапазон"
range_buttons = pn.Row(redraw_btn, clean_btn, sizing_mode="stretch_width")


sidebar_indicators_card = pn.Card(
    ind_select,
    ind_max_points,
    ind_note,
    pn.Row(ind_clear_btn, sizing_mode="stretch_width"),
    ind_params_panel,
    collapsible=True,
    collapsed=True,
    title=ui_i18n.I18N["indicators"][lang.value],
    margin=(0, 0, 6, 0),
)


# ---------------- On-chain master tools (AWS parquet -> indicators/) ----------------
ONCHAIN_MASTER_ENABLED = os.environ.get("MYBOT_ONCHAIN_AUTO", "0") == "1"

onchain_window_days = pn.widgets.IntInput(
    name=ui_i18n.I18N["onchain_window_days"][lang.value],
    value=int(os.environ.get("MYBOT_ONCHAIN_WINDOW_DAYS", "31")),
    # 0 = full rebuild (all available AWS days)
    start=0,
    end=10000,
    step=1,
    sizing_mode="stretch_width",
)

onchain_update_btn = pn.widgets.Button(
    name=ui_i18n.I18N["onchain_update"][lang.value],
    button_type="primary",
    sizing_mode="stretch_width",
)

onchain_reload_btn = pn.widgets.Button(
    name=ui_i18n.I18N["onchain_reload"][lang.value],
    button_type="default",
    sizing_mode="stretch_width",
)

onchain_status = pn.pane.Markdown(
    "",
    sizing_mode="stretch_width",
    margin=(6, 0, 0, 0),
)

onchain_card = pn.Card(
    onchain_window_days,
    pn.Row(onchain_update_btn, onchain_reload_btn, sizing_mode="stretch_width"),
    onchain_status,
    collapsible=True,
    collapsed=True,
    title=ui_i18n.I18N["onchain_tools"][lang.value],
    margin=(0, 0, 6, 0),
)
onchain_card.visible = bool(ONCHAIN_MASTER_ENABLED)

left = pn.Column(
    h_data,
    data_source,
    data_dir,
    csv_select,
    upload,
    symbol,
    tf,
    pn.layout.Divider(margin=(6, 0, 6, 0)),
    h_range,
    date_from,
    date_to,
    warmup_bars,
    warmup_help,
    range_buttons,
    sidebar_indicators_card,
    pn.layout.Divider(margin=(6, 0, 6, 0)),
    sidebar_display_card,
    pn.layout.Divider(margin=(6, 0, 6, 0)),
    sidebar_strategy_card,
    pn.layout.Divider(margin=(6, 0, 6, 0)),
    onchain_card,
    pn.layout.Divider(margin=(6, 0, 6, 0)),
    debug_card,
    status,
    sizing_mode="stretch_width",
    margin=(0, 0, 0, 0),
)

chart_layers_title = pn.pane.Markdown(
    pn.bind(lambda l: f"### {ui_i18n.I18N['chart_layers'][l]}", lang),
    sizing_mode="stretch_width",
    margin=(0, 0, 6, 0),
)

view_toggles = pn.Card(
    chart_layers_title,
    price_log,
    show_trades,
    show_entries,
    show_exits,
    show_uplevel,
    show_dnlevel,
    show_break,
    show_pop_pivots,
    show_pop_levels,
    title=tr("layers"),
    margin=(0, 0, 6, 0),
)

equity_curve_card = pn.Card(
    equity_plot,
    collapsible=True,
    collapsed=False,
    title=ui_i18n.I18N["equity_curve"][lang.value],
    margin=(0, 0, 6, 0),
)

trades_title = pn.pane.Markdown(
    pn.bind(lambda l: f"**{ui_i18n.I18N['trades'][l]}**", lang),
    sizing_mode="stretch_width",
    margin=(8, 0, 4, 0),
)

equity_table_title = pn.pane.Markdown(
    pn.bind(lambda l: f"**{ui_i18n.I18N['equity_table'][l]}**", lang),
    sizing_mode="stretch_width",
    margin=(8, 0, 4, 0),
)

metrics_trades_card = pn.Card(
    metrics_box,
    trades_title,
    trades_table,
    collapsible=True,
    collapsed=False,
    title=ui_i18n.I18N["metrics_trades"][lang.value],
    margin=(0, 0, 6, 0),
)

equity_table_card = pn.Card(
    equity_table_title,
    equity_table,
    collapsible=True,
    collapsed=True,
    title=ui_i18n.I18N["equity_table"][lang.value],
    margin=(0, 0, 6, 0),
)

main = pn.Column(
    pn.pane.Markdown(f"# {APP_TITLE}", margin=(0, 0, 6, 0)),
    view_toggles,
    price_plot,
    equity_curve_card,
    metrics_trades_card,
    equity_table_card,
    sizing_mode="stretch_width",
    margin=(0, 0, 0, 0),
)

template = pn.template.FastListTemplate(
    title=APP_TITLE,
    main_max_width="100%",
    sidebar_width=460,
)

# Важно: не передаём sidebar/main в конструктор шаблона, чтобы избежать пересоздания Bokeh-моделей.
template.sidebar.append(left)
template.main.append(main)

try:
    template.header.append(pn.Row(pn.Spacer(), ws_status_pane, lang_switch, sizing_mode="stretch_width", margin=(0, 10, 0, 0)))
except Exception:
    left.objects.insert(0, lang_switch)

# apply initial labels & visibility after containers exist
_relabel_ui()
_sync_visibility()

template.servable()
