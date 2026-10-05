from __future__ import annotations

from typing import Any, Dict, Optional

import numpy as np
import pandas as pd
import plotly.graph_objects as go

import data_io

from .registry import IndicatorOutput, IndicatorSpec, ParamSpec, register


def _get_col(df: pd.DataFrame, candidates: list[str]) -> Optional[str]:
    for c in candidates:
        if c in df.columns:
            return c
    low = {str(c).lower(): c for c in df.columns}
    for c in candidates:
        k = str(c).lower()
        if k in low:
            return low[k]
    return None


def _norm_df(df_show: pd.DataFrame) -> pd.DataFrame:
    if not isinstance(df_show, pd.DataFrame) or len(df_show) == 0:
        return pd.DataFrame()

    df = df_show.copy()
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        df = df.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)
    return df


def _downsample_xy(ts: pd.Series, y: pd.Series, max_points: int) -> tuple[pd.Series, pd.Series]:
    d = pd.DataFrame({"timestamp": ts, "y": y})
    d = d.dropna(subset=["timestamp"]).reset_index(drop=True)
    d = data_io.downsample_even(d, int(max_points))
    return d["timestamp"], d["y"]


def _compute_sma(df_show: pd.DataFrame, params: Dict[str, Any]) -> IndicatorOutput:
    out = IndicatorOutput()
    df = _norm_df(df_show)
    if len(df) == 0:
        return out

    close_c = _get_col(df, ["close", "Close", "c", "C"])
    if close_c is None:
        out.warnings.append("SMA: no close column")
        return out

    length = int(params.get("length", 20))
    max_points = int(params.get("_max_points", 8000))

    sma = df[close_c].astype(float).rolling(length, min_periods=length).mean()
    out.series["sma"] = sma

    ts, yy = _downsample_xy(df["timestamp"], sma, max_points)

    out.traces.append(
        go.Scattergl(
            x=ts,
            y=yy,
            mode="lines",
            name=f"SMA({length})",
            legendgroup="ind_sma",
        )
    )
    return out


def _compute_ema(df_show: pd.DataFrame, params: Dict[str, Any]) -> IndicatorOutput:
    out = IndicatorOutput()
    df = _norm_df(df_show)
    if len(df) == 0:
        return out

    close_c = _get_col(df, ["close", "Close", "c", "C"])
    if close_c is None:
        out.warnings.append("EMA: no close column")
        return out

    length = int(params.get("length", 20))
    max_points = int(params.get("_max_points", 8000))

    ema = df[close_c].astype(float).ewm(span=length, adjust=False, min_periods=length).mean()
    out.series["ema"] = ema

    ts, yy = _downsample_xy(df["timestamp"], ema, max_points)

    out.traces.append(
        go.Scattergl(
            x=ts,
            y=yy,
            mode="lines",
            name=f"EMA({length})",
            legendgroup="ind_ema",
        )
    )
    return out


def _compute_bb(df_show: pd.DataFrame, params: Dict[str, Any]) -> IndicatorOutput:
    out = IndicatorOutput()
    df = _norm_df(df_show)
    if len(df) == 0:
        return out

    close_c = _get_col(df, ["close", "Close", "c", "C"])
    if close_c is None:
        out.warnings.append("BB: no close column")
        return out

    length = int(params.get("length", 20))
    mult = float(params.get("stdev", 2.0))
    max_points = int(params.get("_max_points", 8000))

    close = df[close_c].astype(float)
    mid = close.rolling(length, min_periods=length).mean()
    sd = close.rolling(length, min_periods=length).std(ddof=0)
    up = mid + mult * sd
    dn = mid - mult * sd

    out.series["bb_mid"] = mid
    out.series["bb_up"] = up
    out.series["bb_dn"] = dn

    ts_mid, y_mid = _downsample_xy(df["timestamp"], mid, max_points)
    ts_up, y_up = _downsample_xy(df["timestamp"], up, max_points)
    ts_dn, y_dn = _downsample_xy(df["timestamp"], dn, max_points)

    out.traces.extend(
        [
            go.Scattergl(x=ts_mid, y=y_mid, mode="lines", name=f"BB mid({length})", legendgroup="ind_bb"),
            go.Scattergl(x=ts_up, y=y_up, mode="lines", name=f"BB up({length},{mult:g})", legendgroup="ind_bb"),
            go.Scattergl(x=ts_dn, y=y_dn, mode="lines", name=f"BB dn({length},{mult:g})", legendgroup="ind_bb"),
        ]
    )
    return out


def _compute_vwap(df_show: pd.DataFrame, params: Dict[str, Any]) -> IndicatorOutput:
    out = IndicatorOutput()
    df = _norm_df(df_show)
    if len(df) == 0:
        return out

    close_c = _get_col(df, ["close", "Close", "c", "C"])
    high_c = _get_col(df, ["high", "High", "h", "H"])
    low_c = _get_col(df, ["low", "Low", "l", "L"])
    vol_c = _get_col(df, ["volume", "Volume", "vol", "v", "V"])

    if vol_c is None or close_c is None:
        out.warnings.append("VWAP: missing close/volume")
        return out

    max_points = int(params.get("_max_points", 8000))

    vol = pd.to_numeric(df[vol_c], errors="coerce").fillna(0.0)
    if high_c is not None and low_c is not None:
        price = (
            pd.to_numeric(df[high_c], errors="coerce")
            + pd.to_numeric(df[low_c], errors="coerce")
            + pd.to_numeric(df[close_c], errors="coerce")
        ) / 3.0
    else:
        price = pd.to_numeric(df[close_c], errors="coerce")

    pv = (price * vol).cumsum()
    vv = vol.cumsum().replace(0.0, np.nan)
    vwap = pv / vv

    out.series["vwap"] = vwap

    ts, yy = _downsample_xy(df["timestamp"], vwap, max_points)

    out.traces.append(
        go.Scattergl(
            x=ts,
            y=yy,
            mode="lines",
            name="VWAP",
            legendgroup="ind_vwap",
        )
    )
    return out


def _compute_rsi(df_show: pd.DataFrame, params: Dict[str, Any]) -> IndicatorOutput:
    out = IndicatorOutput()
    df = _norm_df(df_show)
    if len(df) == 0:
        return out

    close_c = _get_col(df, ["close", "Close", "c", "C"])
    if close_c is None:
        out.warnings.append("RSI: no close column")
        return out

    length = int(params.get("length", 14))
    max_points = int(params.get("_max_points", 8000))

    close = pd.to_numeric(df[close_c], errors="coerce").astype(float)
    delta = close.diff()
    gain = delta.clip(lower=0.0)
    loss = (-delta.clip(upper=0.0))

    alpha = 1.0 / max(1, length)
    avg_gain = gain.ewm(alpha=alpha, adjust=False, min_periods=length).mean()
    avg_loss = loss.ewm(alpha=alpha, adjust=False, min_periods=length).mean()

    rs = avg_gain / avg_loss.replace(0.0, np.nan)
    rsi = 100.0 - (100.0 / (1.0 + rs))

    out.series["rsi"] = rsi

    ts, yy = _downsample_xy(df["timestamp"], rsi, max_points)

    out.traces.append(
        go.Scattergl(
            x=ts,
            y=yy,
            mode="lines",
            name=f"RSI({length})",
            legendgroup="ind_rsi",
            yaxis="y2",
        )
    )

    out.layout["yaxis2"] = {
        "overlaying": "y",
        "side": "right",
        "showgrid": False,
        "zeroline": False,
        "range": [0, 100],
        "title": "RSI",
    }

    if len(ts) > 0:
        x0 = ts.iloc[0]
        x1 = ts.iloc[-1]
        out.layout.setdefault("shapes", [])
        for lvl in [30, 70]:
            out.layout["shapes"].append(
                {
                    "type": "line",
                    "xref": "x",
                    "yref": "y2",
                    "x0": x0,
                    "x1": x1,
                    "y0": lvl,
                    "y1": lvl,
                    "line": {"width": 1, "dash": "dot"},
                }
            )

    return out



# ---------------- Fishnet (Noro's Fishnet-style JMAX net) ----------------

def _jmax_np(src: np.ndarray, length: int) -> np.ndarray:
    """
    Port of Pine v3 jmax() used in Noro's Fishnet.

    Notes:
    - This is recursive; implemented as a tight Python loop.
    - nz(x[1]) behaviour is replicated by initializing state to 0.0.
    """
    src = np.asarray(src, dtype=float)
    n = src.size
    out = np.empty(n, dtype=float)

    L = int(length)
    if L <= 1:
        # Degenerate: return src
        out[:] = src
        return out

    beta = 0.45 * (L - 1) / (0.45 * (L - 1) + 2.0)
    alpha = beta ** 3

    L0 = 0.0
    L1 = 0.0
    L3 = 0.0
    L4 = 0.0

    one_minus_alpha = 1.0 - alpha
    one_minus_beta = 1.0 - beta
    kL3 = (one_minus_alpha * one_minus_alpha)
    a2 = (alpha * alpha)

    for i in range(n):
        x = src[i]

        # L0 := (1-alpha)*src + alpha*nz(L0[1])
        L0 = one_minus_alpha * x + alpha * L0

        # L1 := (src - L0)*(1-beta) + beta*nz(L1[1])
        L1 = (x - L0) * one_minus_beta + beta * L1

        # L2 := L0 + L1
        L2 = L0 + L1

        # L3 := (L2 - nz(L4[1]))*((1-alpha)^2) + (alpha^2)*nz(L3[1])
        L3 = (L2 - L4) * kL3 + a2 * L3

        # L4 := nz(L4[1]) + L3
        L4 = L4 + L3

        out[i] = L4

    return out


def _ffill_trend(sig: np.ndarray) -> np.ndarray:
    """Forward-fill zeros in {-1,0,1} with previous non-zero value."""
    sig = np.asarray(sig, dtype=int)
    if sig.size == 0:
        return sig
    out = sig.copy()
    prev = out[0]
    if prev == 0:
        prev = -1
        out[0] = prev
    for i in range(1, out.size):
        v = out[i]
        if v == 0:
            out[i] = prev
        else:
            prev = v
    return out


def _compute_fishnet(df_show: pd.DataFrame, params: Dict[str, Any]) -> IndicatorOutput:
    """
    Draws multiple JMAX lines (a "net") colored green/red by fast vs slow trend.

    Pine logic:
      ma01 = jmax(close, 10)
      ...
      ma20 = jmax(close, 200)
      trend := ma01 > ma20 ? 1 : ma01 < ma20 ? -1 : trend[1]
      color := green if trend==1 else red
      plot ma01..ma20 with that color
    """
    out = IndicatorOutput()
    df = _norm_df(df_show)
    if len(df) == 0:
        return out

    close_c = _get_col(df, ["close", "Close", "c", "C"])
    if close_c is None:
        out.warnings.append("Fishnet: no close column")
        return out

    start_len = int(params.get("start_len", 10))
    step_len = int(params.get("step", 10))
    count = int(params.get("count", 20))
    width = int(params.get("width", 1))
    opacity = float(params.get("opacity", 0.35))
    max_points = int(params.get("_max_points", 8000))

    # Guardrails
    if count < 2:
        count = 2
    if count > 60:
        out.warnings.append("Fishnet: count capped to 60 for performance")
        count = 60
    if start_len < 1:
        start_len = 1
    if step_len < 1:
        step_len = 1
    if width < 1:
        width = 1
    if opacity <= 0:
        opacity = 0.1
    if opacity > 1:
        opacity = 1.0

    # Downsample for speed (indicator is purely visual overlay).
    d = df[["timestamp", close_c]].copy()
    d = d.dropna(subset=["timestamp"]).reset_index(drop=True)
    d = data_io.downsample_even(d, int(max_points))
    ts = pd.to_datetime(d["timestamp"], utc=True, errors="coerce")
    close = d[close_c].astype(float).to_numpy(dtype=float)

    # Compute net
    lengths = [start_len + step_len * i for i in range(count)]
    mas = [_jmax_np(close, L) for L in lengths]

    ma_fast = mas[0]
    ma_slow = mas[-1]
    sig = np.where(ma_fast > ma_slow, 1, np.where(ma_fast < ma_slow, -1, 0))
    trend = _ffill_trend(sig)

    green = "#00FF7F"
    red = "#DC143C"

    # Plot as segmented lines (Plotly cannot change color within a single trace)
    for i, ma in enumerate(mas, start=1):
        y_up = np.where(trend == 1, ma, np.nan)
        y_dn = np.where(trend == -1, ma, np.nan)

        out.traces.append(
            go.Scattergl(
                x=ts,
                y=y_up,
                mode="lines",
                line=dict(width=width, color=green),
                opacity=opacity,
                name=f"Fishnet {i:02d} up",
                legendgroup="ind_fishnet",
                showlegend=False,
                hoverinfo="skip",
            )
        )
        out.traces.append(
            go.Scattergl(
                x=ts,
                y=y_dn,
                mode="lines",
                line=dict(width=width, color=red),
                opacity=opacity,
                name=f"Fishnet {i:02d} down",
                legendgroup="ind_fishnet",
                showlegend=False,
                hoverinfo="skip",
            )
        )

    return out

# ---------------- Register built-ins ----------------

register(
    IndicatorSpec(
        id="sma",
        title_ru="SMA (скользящая средняя)",
        title_en="SMA (moving average)",
        desc_ru="Простая скользящая средняя по Close.",
        desc_en="Simple moving average of Close.",
        params=[
            ParamSpec(
                key="length",
                kind="int",
                default=20,
                label_ru="Период",
                label_en="Length",
                help_ru="Число баров для SMA.",
                help_en="Number of bars for SMA.",
                min=1,
                max=500,
                step=1,
            )
        ],
        yaxis="y",
        compute=_compute_sma,
    )
)

register(
    IndicatorSpec(
        id="ema",
        title_ru="EMA (экспоненциальная средняя)",
        title_en="EMA (exponential average)",
        desc_ru="Экспоненциальная скользящая средняя по Close.",
        desc_en="Exponential moving average of Close.",
        params=[
            ParamSpec(
                key="length",
                kind="int",
                default=20,
                label_ru="Период",
                label_en="Length",
                help_ru="Число баров для EMA.",
                help_en="Number of bars for EMA.",
                min=1,
                max=500,
                step=1,
            )
        ],
        yaxis="y",
        compute=_compute_ema,
    )
)

register(
    IndicatorSpec(
        id="bb",
        title_ru="Bollinger Bands (полосы Боллинджера)",
        title_en="Bollinger Bands",
        desc_ru="Полосы вокруг SMA: +/- stdev * σ.",
        desc_en="Bands around SMA: +/- stdev * σ.",
        params=[
            ParamSpec(
                key="length",
                kind="int",
                default=20,
                label_ru="Период",
                label_en="Length",
                help_ru="Период SMA/σ.",
                help_en="SMA/σ window.",
                min=1,
                max=500,
                step=1,
            ),
            ParamSpec(
                key="stdev",
                kind="float",
                default=2.0,
                label_ru="Множитель σ",
                label_en="Stdev multiplier",
                help_ru="Ширина полос: множитель стандартного отклонения.",
                help_en="Band width: standard deviation multiplier.",
                min=0.1,
                max=10.0,
                step=0.1,
            ),
        ],
        yaxis="y",
        compute=_compute_bb,
    )
)

register(
    IndicatorSpec(
        id="vwap",
        title_ru="VWAP (средневзвешенная по объёму)",
        title_en="VWAP",
        desc_ru="VWAP требует колонку volume.",
        desc_en="VWAP requires volume column.",
        params=[],
        yaxis="y",
        compute=_compute_vwap,
    )
)

register(
    IndicatorSpec(
        id="rsi",
        title_ru="RSI (индекс относительной силы)",
        title_en="RSI",
        desc_ru="RSI по Close. Рисуется на правой оси (y2) поверх цены.",
        desc_en="RSI of Close. Drawn on right axis (y2) over price.",
        params=[
            ParamSpec(
                key="length",
                kind="int",
                default=14,
                label_ru="Период",
                label_en="Length",
                help_ru="Период для расчёта RSI.",
                help_en="RSI lookback window.",
                min=2,
                max=200,
                step=1,
            )
        ],
        yaxis="y2",
        compute=_compute_rsi,
    )
)



register(
    IndicatorSpec(
        id="fishnet",
        title_ru="Fishnet (сетka JMAX, линии)",
        title_en="Fishnet (JMAX net, lines)",
        desc_ru="Набор из нескольких линий JMAX, окрашенных по тренду (fast vs slow). Аналог Noro's Fishnet.",
        desc_en="Multiple JMAX lines colored by trend (fast vs slow). Noro's Fishnet-style.",
        params=[
            ParamSpec(
                key="start_len",
                kind="int",
                default=10,
                label_ru="Стартовый период",
                label_en="Start length",
                help_ru="Период первой (быстрой) линии JMAX.",
                help_en="Length of the first (fast) JMAX line.",
                min=1,
                max=1000,
                step=1,
            ),
            ParamSpec(
                key="step",
                kind="int",
                default=10,
                label_ru="Шаг периодов",
                label_en="Step",
                help_ru="Шаг между периодами линий (10,20,30...).",
                help_en="Step between line lengths (10,20,30...).",
                min=1,
                max=500,
                step=1,
            ),
            ParamSpec(
                key="count",
                kind="int",
                default=20,
                label_ru="Количество линий",
                label_en="Lines count",
                help_ru="Сколько линий рисовать (больше = гуще, но тяжелее).",
                help_en="How many lines to draw (more = denser, but heavier).",
                min=2,
                max=60,
                step=1,
            ),
            ParamSpec(
                key="width",
                kind="int",
                default=1,
                label_ru="Толщина линии",
                label_en="Line width",
                help_ru="Толщина линий.",
                help_en="Line width.",
                min=1,
                max=5,
                step=1,
            ),
            ParamSpec(
                key="opacity",
                kind="float",
                default=0.35,
                label_ru="Прозрачность",
                label_en="Opacity",
                help_ru="Прозрачность линий (0..1).",
                help_en="Line opacity (0..1).",
                min=0.05,
                max=1.0,
                step=0.05,
            ),
        ],
        yaxis="y",
        compute=_compute_fishnet,
    )
)
