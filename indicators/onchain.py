from __future__ import annotations

"""
Production adapter for MyBot on-chain indicators.

Purpose
-------
Read the canonical UTXO Metrics V4 outputs from:
    /root/mybot/data/onchain_v4

and expose them to the existing indicators registry using stable logical IDs
such as:
    onchain_btc_mvrv_zscore
    onchain_btc_cap_mvrv_cur
    onchain_btc_realized_price
    onchain_btc_sopr
    ...

Important
---------
- This module is READ-ONLY with respect to metric data.
- It never renames, copies, rewrites, or regenerates certified metric CSVs.
- It does not silently fall back to the old /root/mybot/data/onchain dataset.
- MYBOT_ONCHAIN_DIR may explicitly override the root when required.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
import plotly.graph_objects as go

import data_io

from .registry import IndicatorOutput, IndicatorSpec, ParamSpec, get, register

log = logging.getLogger("mybot.indicators.onchain")

APP_ROOT = Path(__file__).resolve().parents[1]  # /root/mybot in production

# ---------------------------------------------------------------------------
# Production data root
# ---------------------------------------------------------------------------

_ONCHAIN_ENV = (os.environ.get("MYBOT_ONCHAIN_DIR") or "").strip()

if _ONCHAIN_ENV:
    ONCHAIN_ROOT = Path(_ONCHAIN_ENV).expanduser()
else:
    # Canonical production output of /root/mybot/utxo_metrics_v4.
    # Deliberately NO implicit fallback to data/onchain: that legacy directory
    # can contain an older/stale horizon and previously caused the UI to stop
    # around 2018 even though the V4 metrics reached 2020-02-16.
    ONCHAIN_ROOT = APP_ROOT / "data" / "onchain_v4"

ONCHAIN_MIN_NON_NAN = int(os.environ.get("MYBOT_ONCHAIN_MIN_NON_NAN", "20"))
ONCHAIN_MIN_COVERAGE = float(os.environ.get("MYBOT_ONCHAIN_MIN_COVERAGE", "0.02"))
ONCHAIN_SKIP_PREFIXES = tuple(
    x.strip()
    for x in os.environ.get("MYBOT_ONCHAIN_SKIP_PREFIXES", "reference_rate").split(",")
    if x.strip()
)

# ---------------------------------------------------------------------------
# Stable UI logical stem -> canonical V4 physical filename stem
# ---------------------------------------------------------------------------

_V4_STEM_MAP: Dict[str, str] = {
    # Stable pre-existing UI IDs
    "mvrv_zscore": "utxo_mvrv_zscore",
    "cap_mvrv_cur": "utxo_mvrv",
    "realized_price": "utxo_realized_price",
    "cap_real_usd": "utxo_cap_real_usd",
    "cap_mrkt_cur_usd": "utxo_cap_mrkt_cur_usd",
    "sply_cur": "utxo_supply_btc",

    # Native V4 metrics
    "sopr": "utxo_sopr",
    "asopr": "utxo_asopr",
    "cdd": "utxo_cdd",
    "dormancy": "utxo_dormancy",
    "live_utxo_count": "utxo_live_utxo_count",
    "created_btc": "utxo_created_btc",
    "spent_btc": "utxo_spent_btc",
    "closed_btc": "utxo_closed_btc",

    "hodl_0_1d": "utxo_hodl_0_1d",
    "hodl_1d_1w": "utxo_hodl_1d_1w",
    "hodl_1w_1m": "utxo_hodl_1w_1m",
    "hodl_1m_3m": "utxo_hodl_1m_3m",
    "hodl_3m_6m": "utxo_hodl_3m_6m",
    "hodl_6m_1y": "utxo_hodl_6m_1y",
    "hodl_1y_2y": "utxo_hodl_1y_2y",
    "hodl_2y_plus": "utxo_hodl_2y_plus",

    "sopr_coverage_cnt": "utxo_sopr_coverage_cnt",
    "sopr_coverage_rate": "utxo_sopr_coverage_rate",
    "asopr_coverage_cnt": "utxo_asopr_coverage_cnt",
    "asopr_coverage_rate": "utxo_asopr_coverage_rate",
}

# Production outputs that are diagnostics/raw inputs rather than chart indicators.
_V4_SKIP_AUTO_STEMS = {
    "utxo_raw_inputs",
}

# cache: (asset, logical_stem) -> (signature, dataframe)
_ONCHAIN_CACHE: Dict[Tuple[str, str], Tuple[Tuple[Any, ...], pd.DataFrame]] = {}
_WARNED: set[str] = set()


def clear_cache() -> None:
    _ONCHAIN_CACHE.clear()


def _warn_once(msg: str) -> None:
    if msg in _WARNED:
        return
    _WARNED.add(msg)
    log.warning(msg)


def _info_once(msg: str) -> None:
    key = f"INFO:{msg}"
    if key in _WARNED:
        return
    _WARNED.add(key)
    log.info(msg)


def _empty_df() -> pd.DataFrame:
    return pd.DataFrame(columns=["timestamp", "value"])


def _physical_stem(stem: str) -> str:
    stem = str(stem or "").strip()
    return _V4_STEM_MAP.get(stem, stem)


def _asset_dir(asset: str) -> Path:
    """
    Supports:
      A) <root>/*.csv          (current BTC V4 layout)
      B) <root>/btc/*.csv      (optional multi-asset layout)
    """
    asset = (asset or "btc").lower()
    d = ONCHAIN_ROOT / asset
    if d.is_dir():
        return d
    return ONCHAIN_ROOT


def _iter_csv_stems(asset: str) -> List[str]:
    d = _asset_dir(asset)
    if not d.is_dir():
        return []

    stems: List[str] = []
    for p in sorted(d.glob("*.csv")):
        stem = p.stem.strip()
        if not stem:
            continue
        if d == ONCHAIN_ROOT and asset.lower() == "btc" and "_eth" in stem.lower():
            continue
        stems.append(stem)
    return stems


def _load_onchain_csv(asset: str, stem: str) -> pd.DataFrame:
    """
    Load one logical metric from its canonical physical V4 CSV.

    Returned columns:
      timestamp : datetime64[ns, UTC]
      value     : float64 / NaN
    """
    asset = (asset or "btc").lower()
    logical_stem = str(stem or "").strip()
    if not logical_stem:
        return _empty_df()

    d = _asset_dir(asset)
    physical_stem = _physical_stem(logical_stem)
    p = d / f"{physical_stem}.csv"

    if not p.is_file():
        _warn_once(
            f"Onchain V4 CSV missing logical={logical_stem} physical={p}"
        )
        return _empty_df()

    try:
        st = p.stat()
        sig = (
            "disk",
            str(p),
            int(st.st_mtime_ns),
            int(st.st_size),
        )
    except Exception:
        sig = ("disk", str(p), None, None)

    ck = (asset, logical_stem)
    cached = _ONCHAIN_CACHE.get(ck)
    if cached is not None and cached[0] == sig:
        return cached[1].copy()

    try:
        df = pd.read_csv(p)
    except Exception as exc:
        _warn_once(f"Onchain V4 CSV read error: {p} ({exc})")
        out = _empty_df()
        _ONCHAIN_CACHE[ck] = (sig, out)
        return out.copy()

    if df is None or len(df) == 0:
        out = _empty_df()
        _ONCHAIN_CACHE[ck] = (sig, out)
        return out.copy()

    cols = {str(c).strip().lower(): c for c in df.columns}
    ts_col = (
        cols.get("timestamp")
        or cols.get("time")
        or cols.get("date")
        or cols.get("datetime")
        or cols.get("ts")
    )
    val_col = (
        cols.get("value")
        or cols.get("val")
        or cols.get("close")
        or cols.get("price")
    )

    if not ts_col or not val_col:
        _warn_once(
            f"Onchain V4 CSV invalid columns: {p} cols={list(df.columns)}"
        )
        out = _empty_df()
        _ONCHAIN_CACHE[ck] = (sig, out)
        return out.copy()

    out = (
        df[[ts_col, val_col]]
        .rename(columns={ts_col: "timestamp", val_col: "value"})
        .copy()
    )
    out["timestamp"] = data_io._parse_timestamp_series(out["timestamp"])
    out["value"] = pd.to_numeric(out["value"], errors="coerce")
    out.loc[np.isinf(out["value"]), "value"] = np.nan
    out = (
        out.dropna(subset=["timestamp"])
        .sort_values("timestamp")
        .drop_duplicates(subset=["timestamp"], keep="last")
        .reset_index(drop=True)
    )

    _ONCHAIN_CACHE[ck] = (sig, out.copy())
    return out


def _norm_df_show(df_show: pd.DataFrame) -> pd.DataFrame:
    if not isinstance(df_show, pd.DataFrame) or len(df_show) == 0:
        return pd.DataFrame(columns=["timestamp", "_pos"])
    if "timestamp" not in df_show.columns:
        return pd.DataFrame(columns=["timestamp", "_pos"])

    df = pd.DataFrame(
        {
            "timestamp": pd.to_datetime(
                df_show["timestamp"], utc=True, errors="coerce"
            ),
            "_pos": np.arange(len(df_show), dtype=np.int64),
        }
    )
    return (
        df.dropna(subset=["timestamp"])
        .sort_values("timestamp")
        .reset_index(drop=True)
    )


def _align_to_show(df_show: pd.DataFrame, series: pd.DataFrame) -> pd.Series:
    """
    Backward-align daily on-chain values to the chart timestamps while preserving
    original df_show row order. Values are never extended beyond the metric's
    final timestamp.
    """
    full = pd.Series(np.full(len(df_show), np.nan, dtype="float64"))

    if not isinstance(df_show, pd.DataFrame) or len(df_show) == 0:
        return full
    if not isinstance(series, pd.DataFrame) or len(series) == 0:
        return full

    left = _norm_df_show(df_show)
    if left.empty:
        return full

    right = series[["timestamp", "value"]].copy()
    right["timestamp"] = pd.to_datetime(
        right["timestamp"], utc=True, errors="coerce"
    )
    right["value"] = pd.to_numeric(right["value"], errors="coerce")
    right = (
        right.dropna(subset=["timestamp"])
        .sort_values("timestamp")
        .drop_duplicates(subset=["timestamp"], keep="last")
        .reset_index(drop=True)
    )

    if right.empty:
        return full

    aligned = pd.merge_asof(
        left[["timestamp", "_pos"]],
        right,
        on="timestamp",
        direction="backward",
    )

    max_ts = right["timestamp"].max()
    if pd.notna(max_ts):
        aligned.loc[aligned["timestamp"] > max_ts, "value"] = np.nan

    pos = aligned["_pos"].to_numpy(dtype=np.int64, copy=False)
    values = pd.to_numeric(aligned["value"], errors="coerce").to_numpy(
        dtype="float64", copy=False
    )
    full.iloc[pos] = values
    return full


def _downsample_xy(
    ts: pd.Series, y: pd.Series, max_points: int
) -> Tuple[pd.Series, pd.Series]:
    d = pd.DataFrame(
        {
            "timestamp": pd.to_datetime(ts, utc=True, errors="coerce"),
            "y": pd.to_numeric(y, errors="coerce"),
        }
    )
    d = d.dropna(subset=["timestamp"]).reset_index(drop=True)

    try:
        d = data_io.downsample_even(d, int(max_points))
    except Exception:
        n = len(d)
        mp = int(max_points or 0)
        if mp > 0 and n > mp:
            step = max(1, n // mp)
            d = d.iloc[::step].reset_index(drop=True)

    return d["timestamp"], d["y"]


def _ensure_yaxis2(layout: Dict[str, Any], title: str = "On-chain") -> None:
    layout.setdefault(
        "yaxis2",
        {
            "overlaying": "y",
            "side": "right",
            "showgrid": False,
            "zeroline": False,
            "title": title,
        },
    )


def _apply_smoothing(y: pd.Series, smooth: str, length: int) -> pd.Series:
    smooth = (smooth or "none").lower()
    length = int(length or 1)

    if length < 2 or smooth == "none":
        return pd.to_numeric(y, errors="coerce")

    yy = pd.to_numeric(y, errors="coerce")

    if smooth == "sma":
        return yy.rolling(length, min_periods=length).mean()
    if smooth == "ema":
        return yy.ewm(
            span=length,
            adjust=False,
            min_periods=length,
        ).mean()

    return yy


def _plot_metric(
    df_show: pd.DataFrame,
    params: Dict[str, Any],
    *,
    ind_id: str,
    asset: str,
    stem: str,
    name: str,
    yaxis: str = "y2",
    as_bars: bool = False,
) -> IndicatorOutput:
    out = IndicatorOutput()

    if not isinstance(df_show, pd.DataFrame) or len(df_show) == 0:
        out.warnings.append("empty display dataframe")
        return out

    if "timestamp" not in df_show.columns:
        out.warnings.append("display dataframe has no timestamp column")
        return out

    daily = _load_onchain_csv(asset, stem)
    if daily.empty:
        out.warnings.append(
            f"missing/empty V4 source: {_asset_dir(asset) / (_physical_stem(stem) + '.csv')}"
        )
        return out

    y = _align_to_show(df_show, daily)
    y = _apply_smoothing(
        y,
        str(params.get("smooth", "none")),
        int(params.get("smooth_len", 30) or 30),
    )

    # Expose full aligned series to the indicator engine.
    out.series[ind_id] = y

    ts = pd.to_datetime(df_show["timestamp"], utc=True, errors="coerce")
    max_points = int(params.get("_max_points", 8000) or 8000)
    x2, y2 = _downsample_xy(ts, y, max_points)

    if as_bars:
        trace = go.Bar(
            x=x2,
            y=y2,
            name=name,
            yaxis=yaxis,
            legendgroup="onchain_v4",
        )
    else:
        trace = go.Scattergl(
            x=x2,
            y=y2,
            mode="lines",
            connectgaps=False,
            name=name,
            yaxis=yaxis,
            legendgroup="onchain_v4",
        )

    out.traces.append(trace)

    if yaxis == "y2":
        _ensure_yaxis2(out.layout, title="On-chain (BTC / UTXO V4)")

    return out


def _make_compute(
    asset: str,
    logical_stem: str,
    title: str,
    *,
    ind_id: str,
    as_bars: bool = False,
):
    def _compute(
        df_show: pd.DataFrame,
        params: Dict[str, Any],
    ) -> IndicatorOutput:
        return _plot_metric(
            df_show,
            params,
            ind_id=ind_id,
            asset=asset,
            stem=logical_stem,
            name=title,
            as_bars=as_bars,
        )

    return _compute


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_COMMON_PARAMS: List[ParamSpec] = [
    ParamSpec(
        key="smooth",
        kind="select",
        default="none",
        label_ru="Сглаживание",
        label_en="Smoothing",
        help_ru="Сглаживание серии перед отрисовкой.",
        help_en="Smooth the series before plotting.",
        options=["none", "sma", "ema"],
    ),
    ParamSpec(
        key="smooth_len",
        kind="int",
        default=30,
        label_ru="Окно сглаживания",
        label_en="Smoothing length",
        help_ru="Период для SMA/EMA.",
        help_en="Window for SMA/EMA.",
        min=2,
        max=500,
        step=1,
    ),
]

# (id_suffix, logical_stem, title_ru, title_en, as_bars)
_CURATED_BTC: List[Tuple[str, str, str, str, bool]] = [
    # Stable IDs kept from the previous UI contract.
    (
        "mvrv_zscore",
        "mvrv_zscore",
        "Onchain BTC: MVRV Z-Score",
        "Onchain BTC: MVRV Z-Score",
        False,
    ),
    (
        "cap_mvrv_cur",
        "cap_mvrv_cur",
        "Onchain BTC: MVRV (ratio)",
        "Onchain BTC: MVRV (ratio)",
        False,
    ),
    (
        "realized_price",
        "realized_price",
        "Onchain BTC: Realized Price",
        "Onchain BTC: Realized Price",
        False,
    ),
    (
        "cap_real_usd",
        "cap_real_usd",
        "Onchain BTC: Realized Cap (USD)",
        "Onchain BTC: Realized Cap (USD)",
        False,
    ),
    (
        "cap_mrkt_cur_usd",
        "cap_mrkt_cur_usd",
        "Onchain BTC: Market Cap (USD)",
        "Onchain BTC: Market Cap (USD)",
        False,
    ),
    (
        "sply_cur",
        "sply_cur",
        "Onchain BTC: Supply",
        "Onchain BTC: Supply",
        False,
    ),

    # Native V4 metrics.
    ("sopr", "sopr", "Onchain BTC: SOPR", "Onchain BTC: SOPR", False),
    ("asopr", "asopr", "Onchain BTC: aSOPR", "Onchain BTC: aSOPR", False),
    ("cdd", "cdd", "Onchain BTC: CDD", "Onchain BTC: CDD", False),
    (
        "dormancy",
        "dormancy",
        "Onchain BTC: Dormancy",
        "Onchain BTC: Dormancy",
        False,
    ),
    (
        "live_utxo_count",
        "live_utxo_count",
        "Onchain BTC: Live UTXO Count",
        "Onchain BTC: Live UTXO Count",
        False,
    ),
    (
        "created_btc",
        "created_btc",
        "Onchain BTC: Created BTC",
        "Onchain BTC: Created BTC",
        True,
    ),
    (
        "spent_btc",
        "spent_btc",
        "Onchain BTC: Spent BTC",
        "Onchain BTC: Spent BTC",
        True,
    ),
    (
        "closed_btc",
        "closed_btc",
        "Onchain BTC: Closed BTC",
        "Onchain BTC: Closed BTC",
        True,
    ),

    (
        "hodl_0_1d",
        "hodl_0_1d",
        "Onchain BTC: HODL 0-1d",
        "Onchain BTC: HODL 0-1d",
        False,
    ),
    (
        "hodl_1d_1w",
        "hodl_1d_1w",
        "Onchain BTC: HODL 1d-1w",
        "Onchain BTC: HODL 1d-1w",
        False,
    ),
    (
        "hodl_1w_1m",
        "hodl_1w_1m",
        "Onchain BTC: HODL 1w-1m",
        "Onchain BTC: HODL 1w-1m",
        False,
    ),
    (
        "hodl_1m_3m",
        "hodl_1m_3m",
        "Onchain BTC: HODL 1m-3m",
        "Onchain BTC: HODL 1m-3m",
        False,
    ),
    (
        "hodl_3m_6m",
        "hodl_3m_6m",
        "Onchain BTC: HODL 3m-6m",
        "Onchain BTC: HODL 3m-6m",
        False,
    ),
    (
        "hodl_6m_1y",
        "hodl_6m_1y",
        "Onchain BTC: HODL 6m-1y",
        "Onchain BTC: HODL 6m-1y",
        False,
    ),
    (
        "hodl_1y_2y",
        "hodl_1y_2y",
        "Onchain BTC: HODL 1y-2y",
        "Onchain BTC: HODL 1y-2y",
        False,
    ),
    (
        "hodl_2y_plus",
        "hodl_2y_plus",
        "Onchain BTC: HODL 2y+",
        "Onchain BTC: HODL 2y+",
        False,
    ),

    (
        "sopr_coverage_cnt",
        "sopr_coverage_cnt",
        "Onchain BTC: SOPR Coverage Count",
        "Onchain BTC: SOPR Coverage Count",
        False,
    ),
    (
        "sopr_coverage_rate",
        "sopr_coverage_rate",
        "Onchain BTC: SOPR Coverage Rate",
        "Onchain BTC: SOPR Coverage Rate",
        False,
    ),
    (
        "asopr_coverage_cnt",
        "asopr_coverage_cnt",
        "Onchain BTC: aSOPR Coverage Count",
        "Onchain BTC: aSOPR Coverage Count",
        False,
    ),
    (
        "asopr_coverage_rate",
        "asopr_coverage_rate",
        "Onchain BTC: aSOPR Coverage Rate",
        "Onchain BTC: aSOPR Coverage Rate",
        False,
    ),
]


def _source_ready(asset: str, logical_stem: str) -> bool:
    physical = _physical_stem(logical_stem)
    p = _asset_dir(asset) / f"{physical}.csv"

    if not p.is_file():
        return False

    try:
        d = pd.read_csv(p, usecols=["value"])
        n = int(len(d))
        if n <= 0:
            return False
        nn = int(pd.to_numeric(d["value"], errors="coerce").notna().sum())
        cov = nn / n
        return (
            nn >= ONCHAIN_MIN_NON_NAN
            and cov >= ONCHAIN_MIN_COVERAGE
        )
    except Exception as exc:
        _warn_once(f"Onchain V4 readiness probe failed: {p} ({exc})")
        return False


def _register_curated_btc() -> None:
    asset = "btc"

    for suffix, logical_stem, title_ru, title_en, as_bars in _CURATED_BTC:
        if not _source_ready(asset, logical_stem):
            _warn_once(
                "Onchain V4 metric not registered because source is "
                f"missing/sparse: logical={logical_stem} "
                f"physical={_asset_dir(asset) / (_physical_stem(logical_stem) + '.csv')}"
            )
            continue

        ind_id = f"onchain_{asset}_{suffix}"
        if get(ind_id) is not None:
            continue

        register(
            IndicatorSpec(
                id=ind_id,
                title_ru=title_ru,
                title_en=title_en,
                desc_ru=(
                    "UTXO Metrics V4: "
                    f"{_physical_stem(logical_stem)}.csv"
                ),
                desc_en=(
                    "UTXO Metrics V4: "
                    f"{_physical_stem(logical_stem)}.csv"
                ),
                params=list(_COMMON_PARAMS),
                yaxis="y2",
                compute=_make_compute(
                    asset,
                    logical_stem,
                    title_en.replace("Onchain BTC: ", ""),
                    ind_id=ind_id,
                    as_bars=as_bars,
                ),
            )
        )


def _auto_register(asset: str) -> None:
    """
    Optional discovery of extra CSVs.

    Canonical V4 files already represented by _V4_STEM_MAP are excluded so
    MYBOT_ONCHAIN_AUTO=1 never creates duplicate onchain_btc_utxo_* entries.
    """
    auto = (
        str(os.getenv("MYBOT_ONCHAIN_AUTO", "0"))
        .strip()
        .lower()
        in ("1", "true", "yes", "on")
    )

    stems = _iter_csv_stems(asset)
    if not stems:
        _info_once(f"Onchain V4 folder missing/empty: {ONCHAIN_ROOT}")
        return

    represented = set(_V4_STEM_MAP.values())
    extra = [
        stem
        for stem in stems
        if stem not in represented
        and stem not in _V4_SKIP_AUTO_STEMS
    ]

    if not auto:
        if extra:
            _info_once(
                f"Onchain auto-registration OFF; hidden extra CSV={len(extra)}"
            )
        return

    for physical_stem in extra:
        low = physical_stem.lower()
        if ONCHAIN_SKIP_PREFIXES and any(
            low.startswith(prefix.lower())
            for prefix in ONCHAIN_SKIP_PREFIXES
        ):
            continue

        p = _asset_dir(asset) / f"{physical_stem}.csv"
        try:
            d = pd.read_csv(p, usecols=["value"])
            n = int(len(d))
            nn = (
                int(pd.to_numeric(d["value"], errors="coerce").notna().sum())
                if n
                else 0
            )
            cov = (nn / n) if n else 0.0
            if (
                n == 0
                or nn < ONCHAIN_MIN_NON_NAN
                or cov < ONCHAIN_MIN_COVERAGE
            ):
                continue
        except Exception as exc:
            _warn_once(
                f"Onchain V4 auto-register probe failed: {p} ({exc})"
            )
            continue

        logical = (
            physical_stem[5:]
            if physical_stem.startswith("utxo_")
            else physical_stem
        )
        ind_id = f"onchain_{asset}_{logical}"
        if get(ind_id) is not None:
            continue

        pretty = logical.replace("_", " ").strip()
        pretty_title = " ".join(
            word.capitalize() for word in pretty.split()
        )

        register(
            IndicatorSpec(
                id=ind_id,
                title_ru=f"Onchain {asset.upper()}: {pretty_title}",
                title_en=f"Onchain {asset.upper()}: {pretty_title}",
                desc_ru=f"UTXO Metrics V4: {physical_stem}.csv",
                desc_en=f"UTXO Metrics V4: {physical_stem}.csv",
                params=list(_COMMON_PARAMS),
                yaxis="y2",
                compute=_make_compute(
                    asset,
                    physical_stem,
                    pretty_title,
                    ind_id=ind_id,
                    as_bars=False,
                ),
            )
        )


def _bootstrap() -> None:
    # Fail closed: do not create a missing data directory and do not silently
    # fall back to the stale legacy dataset.
    if not ONCHAIN_ROOT.is_dir():
        _warn_once(
            f"Canonical onchain V4 root is missing: {ONCHAIN_ROOT}"
        )
        return

    _register_curated_btc()
    _auto_register("btc")


_bootstrap()
