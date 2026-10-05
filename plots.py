# plots.py
from __future__ import annotations

from typing import Any, Dict, Optional, List

import numpy as np
import pandas as pd
import plotly.graph_objects as go

from data_io import downsample_even

HEATMAP_MAX_POINTS = 250_000

# WebGL trace for big point sets
SCATTER = go.Scattergl

def _hex_to_rgba(hex_color: str, alpha: float) -> str:
    s = (hex_color or '').strip()
    if not s:
        s = '#000000'
    if not s.startswith('#'):
        s = '#' + s
    if len(s) == 4:  # #rgb
        s = '#' + ''.join([c * 2 for c in s[1:]])
    try:
        r = int(s[1:3], 16)
        g = int(s[3:5], 16)
        b = int(s[5:7], 16)
    except Exception:
        r, g, b = 0, 0, 0
    a = max(0.0, min(1.0, float(alpha)))
    return f'rgba({r},{g},{b},{a})'



def _is_finite_number(v: Any) -> bool:
    try:
        f = float(v)
    except Exception:
        return False
    return bool(np.isfinite(f))


def _is_valid_x(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, (pd.Timestamp, np.datetime64)):
        return not pd.isna(v)
    if isinstance(v, (int, float, np.integer, np.floating)):
        try:
            return bool(np.isfinite(float(v)))
        except Exception:
            return False
    if isinstance(v, str):
        s = v.strip().lower()
        if not s or s in {"nan", "nat", "none", "null"}:
            return False
        dt = pd.to_datetime(v, utc=True, errors="coerce")
        if not pd.isna(dt):
            return True
        try:
            return bool(np.isfinite(float(v)))
        except Exception:
            return False
    try:
        return not pd.isna(v)
    except Exception:
        return True


def _sanitize_shapes(shapes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop shapes that contain invalid (NaN/inf/NaT) coordinates.

    Plotly can error if layout.shapes includes y0/y1 = NaN or x0/x1 = NaT.
    """
    out: List[Dict[str, Any]] = []
    for sh in shapes or []:
        if not isinstance(sh, dict):
            continue
        if "y0" in sh and not _is_finite_number(sh.get("y0")):
            continue
        if "y1" in sh and not _is_finite_number(sh.get("y1")):
            continue
        if "x0" in sh and not _is_valid_x(sh.get("x0")):
            continue
        if "x1" in sh and not _is_valid_x(sh.get("x1")):
            continue
        out.append(sh)
    return out


def _highlight_color(label: Optional[str]) -> str:
    lbl = (label or "").upper()
    if lbl == "LONG":
        return "green"
    if lbl == "SHORT":
        return "red"
    return "deepskyblue"


def _add_vertical_highlight(fig: go.Figure, t: Optional[pd.Timestamp], label: Optional[str]) -> None:
    if t is None or pd.isna(t):
        return
    color = _highlight_color(label)
    shapes = list(fig.layout.shapes) if getattr(fig.layout, "shapes", None) else []
    shapes.append(
        dict(
            type="line",
            xref="x",
            yref="paper",
            x0=t,
            x1=t,
            y0=0,
            y1=1,
            line=dict(color=color, width=1, dash="dot"),
        )
    )
    fig.update_layout(shapes=shapes)


def _add_backtest_window(
    fig: go.Figure,
    bt_from: Optional[pd.Timestamp],
    bt_to: Optional[pd.Timestamp],
    *,
    show_lines: bool = True,
    show_shade: bool = True,
) -> None:
    """
    Draw backtest window on the PRICE chart:
      - vertical lines at bt_from / bt_to (dashed)
      - optional shaded rectangle between them
    """
    if bt_from is None or bt_to is None:
        return
    try:
        bt_from = pd.to_datetime(bt_from, utc=True, errors="coerce")
        bt_to = pd.to_datetime(bt_to, utc=True, errors="coerce")
    except Exception:
        return
    if pd.isna(bt_from) or pd.isna(bt_to):
        return
    if bt_from >= bt_to:
        return

    shapes = list(fig.layout.shapes) if getattr(fig.layout, "shapes", None) else []

    if show_shade:
        shapes.append(
            dict(
                type="rect",
                xref="x",
                yref="paper",
                x0=bt_from,
                x1=bt_to,
                y0=0,
                y1=1,
                fillcolor="rgba(128,128,128,0.12)",
                line=dict(width=0),
                layer="below",
            )
        )

    if show_lines:
        shapes.append(
            dict(
                type="line",
                xref="x",
                yref="paper",
                x0=bt_from,
                x1=bt_from,
                y0=0,
                y1=1,
                line=dict(color="rgba(128,128,128,0.85)", width=1, dash="dash"),
            )
        )
        shapes.append(
            dict(
                type="line",
                xref="x",
                yref="paper",
                x0=bt_to,
                x1=bt_to,
                y0=0,
                y1=1,
                line=dict(color="rgba(128,128,128,0.85)", width=1, dash="dash"),
            )
        )

    fig.update_layout(shapes=shapes)




def _add_trade_backgrounds(
    fig: go.Figure,
    trades: pd.DataFrame,
    x_min: Any,
    x_max: Any,
) -> None:
    """Shade the whole trade interval on the PRICE chart.

    LONG  -> pale green (50% alpha)
    SHORT -> pale red   (50% alpha)

    Expects columns: entry_time, exit_time, side (1 for long, -1 for short).
    """
    if trades is None or not isinstance(trades, pd.DataFrame) or len(trades) == 0:
        return
    if "entry_time" not in trades.columns:
        return

    t = trades.copy()

    # Normalize times
    t["entry_time"] = pd.to_datetime(t["entry_time"], utc=True, errors="coerce")
    if "exit_time" in t.columns:
        t["exit_time"] = pd.to_datetime(t["exit_time"], utc=True, errors="coerce")
    else:
        t["exit_time"] = pd.NaT

    # Side: 1 (long), -1 (short)
    if "side" in t.columns:
        t["side"] = pd.to_numeric(t["side"], errors="coerce").fillna(0).astype(int)
    else:
        return

    x_min = pd.to_datetime(x_min, utc=True, errors="coerce")
    x_max = pd.to_datetime(x_max, utc=True, errors="coerce")
    if pd.isna(x_min) or pd.isna(x_max) or x_min >= x_max:
        return

    shapes = list(fig.layout.shapes) if getattr(fig.layout, "shapes", None) else []

    fill_long = "rgba(144,238,144,0.5)"   # lightgreen
    fill_short = "rgba(255,182,193,0.5)"  # lightpink

    # Only draw trades that overlap the visible window
    for _, r in t.iterrows():
        et = r.get("entry_time")
        xt = r.get("exit_time")
        side = int(r.get("side", 0))

        if et is None or pd.isna(et):
            continue

        # Open trade -> shade until x_max
        if xt is None or pd.isna(xt):
            xt = x_max

        if xt <= et:
            continue

        # Overlap with view
        x0 = max(et, x_min)
        x1 = min(xt, x_max)
        if x1 <= x0:
            continue

        if side == 1:
            fill = fill_long
        elif side == -1:
            fill = fill_short
        else:
            continue

        shapes.append(
            dict(
                type="rect",
                xref="x",
                yref="paper",
                x0=x0,
                x1=x1,
                y0=0.0,
                y1=1.0,
                fillcolor=fill,
                opacity=1.0,  # alpha already in rgba
                line=dict(width=0),
                layer="below",
            )
        )

    if shapes:
        fig.update_layout(shapes=_sanitize_shapes(shapes))

def hist2d_heatmap(ts: pd.Series, px: pd.Series, time_bins: int, price_bins: int) -> go.Heatmap:
    ts = pd.to_datetime(ts, utc=True, errors="coerce")
    px = pd.to_numeric(px, errors="coerce")
    m = ts.notna() & px.notna()
    ts = ts[m]
    px = px[m].astype(float)

    if len(ts) < 10:
        return go.Heatmap(z=[[0]], x=[0], y=[0], showscale=False, name="Density")

    if len(ts) > HEATMAP_MAX_POINTS:
        idx = np.linspace(0, len(ts) - 1, HEATMAP_MAX_POINTS).astype(int)
        ts = ts.iloc[idx]
        px = px.iloc[idx]

    tsec = (ts.astype("int64") // 10**9).to_numpy(dtype=np.int64)
    pval = px.to_numpy(dtype=float)

    time_bins = int(max(50, min(1200, time_bins)))
    price_bins = int(max(50, min(300, price_bins)))

    t_min, t_max = int(tsec.min()), int(tsec.max())
    p_min, p_max = float(np.nanmin(pval)), float(np.nanmax(pval))
    if t_min == t_max:
        t_max = t_min + 1
    if p_min == p_max:
        p_max = p_min + 1.0

    H, t_edges, p_edges = np.histogram2d(
        tsec,
        pval,
        bins=[time_bins, price_bins],
        range=[[t_min, t_max], [p_min, p_max]],
    )

    t_centers = (t_edges[:-1] + t_edges[1:]) / 2.0
    p_centers = (p_edges[:-1] + p_edges[1:]) / 2.0
    t_dt = pd.to_datetime(t_centers, unit="s", utc=True)

    return go.Heatmap(
        z=H.T,
        x=t_dt,
        y=p_centers,
        name="Density",
        showscale=False,
        hovertemplate="t=%{x}<br>p=%{y:.2f}<br>cnt=%{z}<extra></extra>",
    )


def build_price_figure(
    df_show: pd.DataFrame,
    res: Optional[Any],
    *,
    chart_mode: str,
    max_points: int,
    hm_time_bins: int,
    hm_price_bins: int,
    is_py: bool,
    show_flags: Dict[str, bool],
    fishnet_style: Optional[Dict[str, Any]] = None,
    highlight_time: Optional[pd.Timestamp] = None,
    highlight_label: Optional[str] = None,
    bt_from: Optional[pd.Timestamp] = None,
    bt_to: Optional[pd.Timestamp] = None,
    show_bt_lines: bool = True,
    show_bt_shade: bool = True,
    indicator_traces: Optional[List[Any]] = None,
    indicator_layout: Optional[Dict[str, Any]] = None,
    price_log: bool = False,
) -> go.Figure:
    fig = go.Figure()

    # Price base
    price_df = df_show[["timestamp", "open", "high", "low", "close"]].copy()
    price_df["timestamp"] = pd.to_datetime(price_df["timestamp"], utc=True, errors="coerce")
    price_df = price_df.dropna(subset=["timestamp"]).sort_values("timestamp")

    # Optional log scale for PRICE axis: drop non-positive OHLC (log axis cannot display <=0)
    if price_log:
        try:
            m = (price_df[['open','high','low','close']].astype(float) > 0).all(axis=1)
            price_df = price_df.loc[m].copy()
        except Exception:
            pass

    ohlc_ds = downsample_even(price_df, int(max_points))

    if chart_mode == "Heatmap":
        hm = hist2d_heatmap(price_df["timestamp"], price_df["close"], int(hm_time_bins), int(hm_price_bins))
        fig.add_trace(hm)

        line_df = downsample_even(price_df[["timestamp", "close"]], int(max_points))
        fig.add_trace(
            SCATTER(
                x=line_df["timestamp"],
                y=line_df["close"],
                mode="lines",
                name="Price",
                line=dict(width=1),
            )
        )

    elif chart_mode == "Candles (B/W)":
        fig.add_trace(
            go.Candlestick(
                x=ohlc_ds["timestamp"],
                open=ohlc_ds["open"],
                high=ohlc_ds["high"],
                low=ohlc_ds["low"],
                close=ohlc_ds["close"],
                name="Candles",
                increasing_line_color="black",
                decreasing_line_color="black",
                increasing_fillcolor="white",
                decreasing_fillcolor="black",
            )
        )
    else:
        line_df = downsample_even(price_df[["timestamp", "close"]], int(max_points))
        fig.add_trace(
            SCATTER(
                x=line_df["timestamp"],
                y=line_df["close"],
                mode="lines",
                name="Price",
                line=dict(width=1),
            )
        )

    if len(ohlc_ds):
        x_min = ohlc_ds["timestamp"].min()
        x_max = ohlc_ds["timestamp"].max()
    else:
        x_min = price_df["timestamp"].min()
        x_max = price_df["timestamp"].max()

    # Backtest window (visual only)
    _add_backtest_window(fig, bt_from, bt_to, show_lines=show_bt_lines, show_shade=show_bt_shade)

    # Show flags (ensure defaults even if there are no trades)
    show_trades = bool((show_flags or {}).get("show_trades", True))
    show_entries = bool((show_flags or {}).get("show_entries", True))
    show_exits = bool((show_flags or {}).get("show_exits", True))
    show_break = bool((show_flags or {}).get("show_break", False))
    show_uplevel = bool((show_flags or {}).get("show_uplevel", False))
    show_dnlevel = bool((show_flags or {}).get("show_dnlevel", False))
    show_pop_pivots = bool((show_flags or {}).get("show_pop_pivots", False))
    show_pop_levels = bool((show_flags or {}).get("show_pop_levels", False))

    # Trades markers
    if res is not None and hasattr(res, "trades") and isinstance(res.trades, pd.DataFrame) and len(res.trades) > 0:
        t = res.trades.copy()
        if "entry_time" in t.columns:
            t["entry_time"] = pd.to_datetime(t["entry_time"], utc=True, errors="coerce")
        if "exit_time" in t.columns:
            t["exit_time"] = pd.to_datetime(t["exit_time"], utc=True, errors="coerce")
        if show_trades:
            _add_trade_backgrounds(fig, t, x_min, x_max)


        if show_trades and show_entries and {"entry_time", "entry_price"}.issubset(t.columns):
            te = t.dropna(subset=["entry_time", "entry_price"]).copy()
            te = te[(te["entry_time"] >= x_min) & (te["entry_time"] <= x_max)]
            if "side" in te.columns:
                te["side"] = pd.to_numeric(te["side"], errors="coerce").fillna(0).astype(int)

            te_long = te[te["side"] == 1] if "side" in te.columns else te
            te_short = te[te["side"] == -1] if "side" in te.columns else te.iloc[0:0]

            if len(te_long):
                fig.add_trace(
                    SCATTER(
                        x=te_long["entry_time"],
                        y=te_long["entry_price"],
                        mode="markers",
                        name="Entry LONG",
                        marker=dict(size=20, symbol="triangle-up", color="green"),
                    )
                )
            if len(te_short):
                fig.add_trace(
                    SCATTER(
                        x=te_short["entry_time"],
                        y=te_short["entry_price"],
                        mode="markers",
                        name="Entry SHORT",
                        marker=dict(size=20, symbol="triangle-down", color="red"),
                    )
                )

        if show_trades and show_exits and {"exit_time", "exit_price"}.issubset(t.columns):
            tx = t.dropna(subset=["exit_time", "exit_price"]).copy()
            tx = tx[(tx["exit_time"] >= x_min) & (tx["exit_time"] <= x_max)]
            if "side" in tx.columns:
                tx["side"] = pd.to_numeric(tx["side"], errors="coerce").fillna(0).astype(int)

            tx_long = tx[tx["side"] == 1] if "side" in tx.columns else tx
            tx_short = tx[tx["side"] == -1] if "side" in tx.columns else tx.iloc[0:0]

            if len(tx_long):
                fig.add_trace(
                    SCATTER(
                        x=tx_long["exit_time"],
                        y=tx_long["exit_price"],
                        mode="markers",
                        name="Exit LONG",
                        marker=dict(size=9, symbol="x", color="blue"),
                    )
                )
            if len(tx_short):
                fig.add_trace(
                    SCATTER(
                        x=tx_short["exit_time"],
                        y=tx_short["exit_price"],
                        mode="markers",
                        name="Exit SHORT",
                        marker=dict(size=9, symbol="x", color="blue"),
                    )
                )

        # Break levels as dotted lines (PY-only + checkbox)
        if is_py and show_break and {"break_level", "entry_time", "exit_time"}.issubset(t.columns):
            t2 = t.copy()
            t2["break_level"] = pd.to_numeric(t2["break_level"], errors="coerce")
            t2 = t2.dropna(subset=["break_level", "entry_time", "exit_time"]).copy()
            t2 = t2[(t2["exit_time"] >= x_min) & (t2["entry_time"] <= x_max)]

            shapes = list(fig.layout.shapes) if getattr(fig.layout, "shapes", None) else []
            for _, r in t2.iterrows():
                y = float(r["break_level"])
                x0 = r["entry_time"]
                x1 = r["exit_time"]
                bt = str(r.get("break_type", "") or "")
                color = "green" if "UP" in bt else ("red" if "DN" in bt else "blue")
                if _is_finite_number(y) and _is_valid_x(x0) and _is_valid_x(x1):
                    shapes.append(
                        dict(
                            type="line",
                            xref="x",
                            yref="y",
                            x0=x0,
                            x1=x1,
                            y0=float(y),
                            y1=float(y),
                            line=dict(color=color, width=1, dash="dot"),
                        )
                    )
            fig.update_layout(shapes=_sanitize_shapes(shapes))

        # uplevel/dnlevel (PY-only + checkbox)
        if is_py and hasattr(res, "equity") and isinstance(res.equity, pd.DataFrame) and len(res.equity) > 0:
            eq = res.equity.copy()
            if "timestamp" in eq.columns:
                eq["timestamp"] = pd.to_datetime(eq["timestamp"], utc=True, errors="coerce")
            eq = eq.dropna(subset=["timestamp"]).sort_values("timestamp")
            eq_ds = downsample_even(eq, 8000)

            if show_uplevel and "uplevel" in eq_ds.columns:
                y = pd.to_numeric(eq_ds["uplevel"], errors="coerce")
                m = y.notna()
                fig.add_trace(
                    SCATTER(
                        x=eq_ds.loc[m, "timestamp"],
                        y=y.loc[m],
                        mode="lines",
                        name="uplevel",
                        line=dict(width=1, dash="dash", color="green"),
                    )
                )
            if show_dnlevel and "dnlevel" in eq_ds.columns:
                y = pd.to_numeric(eq_ds["dnlevel"], errors="coerce")
                m = y.notna()
                fig.add_trace(
                    SCATTER(
                        x=eq_ds.loc[m, "timestamp"],
                        y=y.loc[m],
                        mode="lines",
                        name="dnlevel",
                        line=dict(width=1, dash="dash", color="red"),
                    )
                )

            # PoP (Pivot of Pivot) overlays
            if show_pop_pivots and ("pop_hprice" in eq_ds.columns or "pop_lprice" in eq_ds.columns):
                if "pop_hprice" in eq_ds.columns:
                    y = pd.to_numeric(eq_ds["pop_hprice"], errors="coerce")
                    m = y.notna()
                    fig.add_trace(
                        SCATTER(
                            x=eq_ds.loc[m, "timestamp"],
                            y=y.loc[m],
                            mode="lines",
                            name="PoP hprice",
                            line=dict(width=1, dash="solid", color="green"),
                        )
                    )
                if "pop_lprice" in eq_ds.columns:
                    y = pd.to_numeric(eq_ds["pop_lprice"], errors="coerce")
                    m = y.notna()
                    fig.add_trace(
                        SCATTER(
                            x=eq_ds.loc[m, "timestamp"],
                            y=y.loc[m],
                            mode="lines",
                            name="PoP lprice",
                            line=dict(width=1, dash="solid", color="red"),
                        )
                    )

            if show_pop_levels and ("pop_pphprice" in eq_ds.columns or "pop_pplprice" in eq_ds.columns):
                if "pop_pphprice" in eq_ds.columns:
                    y = pd.to_numeric(eq_ds["pop_pphprice"], errors="coerce")
                    m = y.notna()
                    fig.add_trace(
                        SCATTER(
                            x=eq_ds.loc[m, "timestamp"],
                            y=y.loc[m],
                            mode="lines",
                            name="PoP PPH",
                            line=dict(width=2, dash="solid", color="green"),
                        )
                    )
                if "pop_pplprice" in eq_ds.columns:
                    y = pd.to_numeric(eq_ds["pop_pplprice"], errors="coerce")
                    m = y.notna()
                    fig.add_trace(
                        SCATTER(
                            x=eq_ds.loc[m, "timestamp"],
                            y=y.loc[m],
                            mode="lines",
                            name="PoP PPL",
                            line=dict(width=2, dash="solid", color="red"),
                        )
                    )
            # Fishnet (JMAX) lines (PoP) - optional, shown only when enabled in UI
            show_pop_fishnet = bool((show_flags or {}).get('show_pop_fishnet', False))
            if show_pop_fishnet:
                ma_cols = [c for c in eq_ds.columns if c.startswith('fishnet_ma_')]
                if ma_cols:
                    def _k(c: str) -> int:
                        try:
                            return int(c.split('_')[-1])
                        except Exception:
                            return 10**9
                    ma_cols = sorted(ma_cols, key=_k)

                    trend = None
                    if 'fishnet_trend' in eq_ds.columns:
                        trend = pd.to_numeric(eq_ds['fishnet_trend'], errors='coerce').fillna(0).astype(int).values

                    opacity = float((fishnet_style or {}).get('opacity', 0.35))
                    width = int((fishnet_style or {}).get('width', 1))
                    col_up = str((fishnet_style or {}).get('color_up', '#00FF7F'))
                    col_dn = str((fishnet_style or {}).get('color_dn', '#DC143C'))
                    rgba_up = _hex_to_rgba(col_up, opacity)
                    rgba_dn = _hex_to_rgba(col_dn, opacity)

                    for col in ma_cols:
                        y = pd.to_numeric(eq_ds[col], errors='coerce')
                        if trend is None:
                            m = y.notna()
                            fig.add_trace(
                                SCATTER(
                                    x=eq_ds.loc[m, 'timestamp'],
                                    y=y.loc[m],
                                    mode='lines',
                                    name=col,
                                    showlegend=False,
                                    connectgaps=False,
                                    line=dict(width=width, color=rgba_up),
                                )
                            )
                        else:
                            yg = y.where(trend == 1)
                            yr = y.where(trend == -1)
                            mg = yg.notna()
                            mr = yr.notna()
                            if mg.any():
                                fig.add_trace(
                                    SCATTER(
                                        x=eq_ds['timestamp'],
                                        y=yg,
                                        mode='lines',
                                        name=col,
                                        showlegend=False,
                                        connectgaps=False,
                                        line=dict(width=width, color=rgba_up),
                                    )
                                )
                            if mr.any():
                                fig.add_trace(
                                    SCATTER(
                                        x=eq_ds['timestamp'],
                                        y=yr,
                                        mode='lines',
                                        name=col,
                                        showlegend=False,
                                        connectgaps=False,
                                        line=dict(width=width, color=rgba_dn),
                                    )
                                )




    # Indicators layer (must be added after strategy overlays to render on top)
    if indicator_traces:
        for tr in indicator_traces:
            try:
                fig.add_trace(tr)
            except Exception:
                pass

    if indicator_layout:
        try:
            # Merge shapes (append)
            if "shapes" in indicator_layout:
                cur_shapes = list(fig.layout.shapes) if getattr(fig.layout, "shapes", None) else []
                add_shapes = list(indicator_layout.get("shapes") or [])
                fig.update_layout(shapes=_sanitize_shapes(cur_shapes + add_shapes))
            # Apply remaining layout keys
            rest = {k: v for k, v in dict(indicator_layout).items() if k != "shapes"}
            if rest:
                fig.update_layout(**rest)
        except Exception:
            pass

    fig.update_layout(height=620, margin=dict(l=10, r=10, t=30, b=10))

    # Apply log/linear to PRICE axis only (on-chain indicators use y2)
    try:
        fig.update_layout(yaxis=dict(type=("log" if price_log else "linear")))
    except Exception:
        pass

    # Selection highlight (vertical)
    _add_vertical_highlight(fig, highlight_time, highlight_label)

    return fig


def build_equity_figure(
    eq_df: pd.DataFrame,
    *,
    trades_df: Optional[pd.DataFrame] = None,
    highlight_time: Optional[pd.Timestamp] = None,
    highlight_label: Optional[pd.Timestamp] = None,
) -> go.Figure:
    """Equity curve figure.

    Note: annotations are computed from the visible equity window (eq_df). If trades_df is provided,
    win-rate and trades count are computed for closed trades whose exit_time falls inside the same window.
    """
    fig = go.Figure()
    if not isinstance(eq_df, pd.DataFrame) or len(eq_df) < 2:
        fig.update_layout(height=260, margin=dict(l=10, r=10, t=10, b=10))
        _add_vertical_highlight(fig, highlight_time, str(highlight_label) if highlight_label is not None else None)
        return fig

    eq = eq_df.copy()
    eq["timestamp"] = pd.to_datetime(eq["timestamp"], utc=True, errors="coerce")
    eq["equity"] = pd.to_numeric(eq["equity"], errors="coerce")
    eq = eq.dropna(subset=["timestamp", "equity"]).sort_values("timestamp")
    if len(eq) < 2:
        fig.update_layout(height=260, margin=dict(l=10, r=10, t=10, b=10))
        _add_vertical_highlight(fig, highlight_time, str(highlight_label) if highlight_label is not None else None)
        return fig

    # Downsample for rendering
    eq_line = downsample_even(eq[["timestamp", "equity"]], 5000)
    fig.add_trace(
        SCATTER(
            x=eq_line["timestamp"],
            y=eq_line["equity"],
            mode="lines",
            name="Equity",
            line=dict(width=2),
        )
    )
    fig.update_layout(height=260, margin=dict(l=10, r=10, t=10, b=10))

    # --- Stats from visible window
    try:
        first = float(eq["equity"].iloc[0])
        last = float(eq["equity"].iloc[-1])
        start_ts = pd.to_datetime(eq["timestamp"].iloc[0], utc=True)
        end_ts = pd.to_datetime(eq["timestamp"].iloc[-1], utc=True)

        # Profit %
        pct = None
        if first != 0.0 and np.isfinite(first) and np.isfinite(last):
            pct = (last / first - 1.0) * 100.0

        # Max drawdown % (absolute)
        max_dd_pct = None
        try:
            y = eq["equity"].to_numpy(dtype=float)
            if len(y) >= 2 and np.all(np.isfinite(y)) and np.nanmin(y) > 0:
                peak = np.maximum.accumulate(y)
                dd = (y / peak) - 1.0
                max_dd_pct = float(abs(np.nanmin(dd)) * 100.0)
        except Exception:
            max_dd_pct = None

        # Trades + win rate inside window (by exit_time)
        trades_n = None
        win_rate = None
        try:
            if isinstance(trades_df, pd.DataFrame) and len(trades_df) > 0:
                t = trades_df.copy()
                # choose a close time column
                time_col = None
                for c in ["exit_time", "close_time", "time_close", "timestamp_exit", "exit_ts"]:
                    if c in t.columns:
                        time_col = c
                        break
                if time_col is not None:
                    t[time_col] = pd.to_datetime(t[time_col], utc=True, errors="coerce")
                    tf = t[(t[time_col] >= start_ts) & (t[time_col] <= end_ts)].copy()
                    trades_n = int(len(tf))

                    # win/loss column
                    pnl_col = None
                    for c in ["gross_return", "pnl", "profit", "return", "ret", "net_return"]:
                        if c in tf.columns:
                            pnl_col = c
                            break
                    if trades_n > 0 and pnl_col is not None:
                        pnls = pd.to_numeric(tf[pnl_col], errors="coerce")
                        wins = int((pnls > 0).sum())
                        win_rate = wins / trades_n if trades_n else None
        except Exception:
            trades_n = None
            win_rate = None

        # --- Annotations (RU by default; keep simple and compact)
        # Main profit line (green/red)
        if pct is not None and np.isfinite(pct):
            if pct >= 0:
                profit_txt = f"Profit +{pct:.1f}%"
                profit_color = "green"
            else:
                profit_txt = f"Loss {pct:.1f}%"
                profit_color = "red"

            # Compose extra lines (shown under Profit)
            extra_lines = []
            if max_dd_pct is not None and np.isfinite(max_dd_pct):
                extra_lines.append(f"Макс. Просадка {max_dd_pct:.1f}%")
            if win_rate is not None and np.isfinite(win_rate):
                extra_lines.append(f"Прибыльных сделок {win_rate*100.0:.0f}%")
            if trades_n is not None:
                extra_lines.append(f"Сделок {trades_n}шт,")
            # Range (always)
            try:
                s1 = start_ts.strftime("%Y-%m-%d")
                s2 = end_ts.strftime("%Y-%m-%d")
                extra_lines.append(f"Диапазон {s1} по {s2}")
            except Exception:
                pass

            hover_all = "<br>".join([profit_txt] + extra_lines)

            # Profit line
            fig.add_annotation(
                xref="paper",
                yref="paper",
                x=0.01,
                y=0.99,
                text=profit_txt,
                showarrow=False,
                font=dict(size=18, color=profit_color),
                align="left",
                xanchor="left",
                yanchor="top",
                hovertext=hover_all,
            )

            # Extra lines (smaller)
            y0 = 0.90
            dy = 0.075
            for i, line in enumerate(extra_lines[:6]):  # safety cap
                fig.add_annotation(
                    xref="paper",
                    yref="paper",
                    x=0.01,
                    y=y0 - i * dy,
                    text=line,
                    showarrow=False,
                    font=dict(size=12, color="#444"),
                    align="left",
                    xanchor="left",
                    yanchor="top",
                    hovertext=hover_all,
                )

    except Exception:
        pass

    # Selection highlight (vertical)
    _add_vertical_highlight(fig, highlight_time, str(highlight_label) if highlight_label is not None else None)

    return fig

    eq = eq_df.copy()
    eq["timestamp"] = pd.to_datetime(eq["timestamp"], utc=True, errors="coerce")
    eq["equity"] = pd.to_numeric(eq["equity"], errors="coerce")
    eq = eq.dropna(subset=["timestamp", "equity"]).sort_values("timestamp")

    eq_line = downsample_even(eq[["timestamp", "equity"]], 5000)

    fig.add_trace(
        SCATTER(
            x=eq_line["timestamp"],
            y=eq_line["equity"],
            mode="lines",
            name="Equity",
            line=dict(width=2),
        )
    )
    fig.update_layout(height=260, margin=dict(l=10, r=10, t=10, b=10))

    # Profit/Loss annotation (top-left, single line)
    try:
        first = float(eq["equity"].iloc[0])
        last = float(eq["equity"].iloc[-1])
        if first != 0.0 and np.isfinite(first) and np.isfinite(last):
            pct = (last / first - 1.0) * 100.0
            if pct >= 0:
                txt = f"Profit +{pct:.1f}%"
                color = "green"
            else:
                txt = f"Loss {pct:.1f}%"
                color = "red"
            fig.add_annotation(
                xref="paper",
                yref="paper",
                x=0.01,
                y=0.99,
                text=txt,
                showarrow=False,
                font=dict(size=18, color=color),
                align="left",
                xanchor="left",
                yanchor="top",
            )
    except Exception:
        pass

    # Selection highlight (vertical)
    _add_vertical_highlight(fig, highlight_time, str(highlight_label) if highlight_label is not None else None)

    return fig
