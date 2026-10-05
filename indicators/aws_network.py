from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Tuple

import numpy as np
import pandas as pd
import plotly.graph_objects as go

from .registry import IndicatorOutput, IndicatorSpec, register, ParamSpec

log = logging.getLogger("mybot.indicators.aws_network")

# Where master ETL writes per-indicator datasets
IND_ROOT = Path("/opt/mybot_data/indicators")

# In-memory cache: (path, mtime_ns, size) -> dataframe
_CACHE: Dict[Tuple[str, int, int], pd.DataFrame] = {}


def clear_cache() -> None:
    """Clear AWS indicator read cache (used by on-chain master tools)."""
    _CACHE.clear()


def _read_daily_series(stem: str) -> pd.DataFrame:
    """Read daily parquet with columns [d,value] or [timestamp,value].

    Normalizes:
      - timestamp: datetime64[ns, UTC]
      - value: float64
    """
    p = IND_ROOT / "network" / stem / f"{stem}_daily.parquet"
    if not p.exists():
        raise FileNotFoundError(f"Missing indicator file: {p}")

    st = p.stat()
    ck = (str(p), int(st.st_mtime_ns), int(st.st_size))
    if ck in _CACHE:
        return _CACHE[ck].copy()

    df = pd.read_parquet(p)

    # Accept either 'timestamp' or legacy 'd'
    if "timestamp" in df.columns:
        ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    elif "d" in df.columns:
        ts = pd.to_datetime(df["d"], utc=True, errors="coerce")
    else:
        raise ValueError(f"{p} has no 'timestamp' or 'd' column (cols={list(df.columns)})")

    if "value" not in df.columns:
        for c in ("v", "y", stem):
            if c in df.columns:
                df = df.rename(columns={c: "value"})
                break

    if "value" not in df.columns:
        raise ValueError(f"{p} has no 'value' column (cols={list(df.columns)})")

    out = pd.DataFrame(
        {
            "timestamp": ts,
            "value": pd.to_numeric(df["value"], errors="coerce"),
        }
    )
    out = out.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)

    # keep cache small & safe across updates
    _CACHE.clear()
    _CACHE[ck] = out.copy()
    return out


def _align_to_show(df_show: pd.DataFrame, daily: pd.DataFrame) -> pd.Series:
    """Align daily values to df_show timestamps (merge_asof backward).

    Returns float64 Series length == len(df_show) with np.nan for missing.
    """
    if not isinstance(df_show, pd.DataFrame) or len(df_show) == 0:
        return pd.Series([], dtype="float64")

    if "timestamp" not in df_show.columns:
        raise ValueError("df_show has no 'timestamp' column")

    left = pd.DataFrame({"timestamp": pd.to_datetime(df_show["timestamp"], utc=True, errors="coerce")})
    left["_pos"] = range(len(left))
    left = left.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)

    right = daily[["timestamp", "value"]].copy()
    right["timestamp"] = pd.to_datetime(right["timestamp"], utc=True, errors="coerce")
    right["value"] = pd.to_numeric(right["value"], errors="coerce")
    right = right.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)

    full = pd.Series(np.full(len(df_show), np.nan, dtype="float64"))
    if len(right) == 0 or len(left) == 0:
        return full

    aligned = pd.merge_asof(left[["timestamp", "_pos"]], right, on="timestamp", direction="backward")
    full.iloc[aligned["_pos"].to_numpy()] = aligned["value"].to_numpy(dtype="float64", copy=False)
    return full


def _downsample(ts: pd.Series, y: pd.Series, max_points: int) -> Tuple[pd.Series, pd.Series]:
    d = pd.DataFrame({"ts": ts, "y": y})
    d = d.dropna(subset=["ts"]).reset_index(drop=True)
    n = len(d)
    if max_points is None or max_points <= 0 or n <= max_points:
        return d["ts"], d["y"]
    step = max(1, n // int(max_points))
    return d["ts"].iloc[::step], d["y"].iloc[::step]


def _ensure_yaxis2(layout: Dict[str, Any], title: str = "Network") -> None:
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


def _make_daily_indicator(
    *,
    ind_id: str,
    stem: str,
    title_ru: str,
    title_en: str,
    yaxis: str = "y2",
    legendgroup: str = "aws_network",
) -> None:
    def _compute(df_show: pd.DataFrame, params: Dict[str, Any]) -> IndicatorOutput:
        out = IndicatorOutput()
        max_points = int(params.get("_max_points", 8000) or 8000)

        daily = _read_daily_series(stem)
        y = _align_to_show(df_show, daily)
        ts = pd.to_datetime(df_show["timestamp"], utc=True, errors="coerce")

        x2, y2 = _downsample(ts, y, max_points)

        # IMPORTANT: expose aligned series for diagnostics/other layers
        out.series[ind_id] = y

        out.traces.append(
            go.Scattergl(
                x=x2,
                y=y2,
                mode="lines",
                line={"shape": "hv"},
                connectgaps=True,
                name=title_en,
                yaxis=yaxis,
                legendgroup=legendgroup,
            )
        )
        if yaxis == "y2":
            _ensure_yaxis2(out.layout, title="Network (AWS)")
        return out

    register(
        IndicatorSpec(
            id=ind_id,
            title_ru=title_ru,
            title_en=title_en,
            desc_ru="Индикатор по данным AWS Public Blockchain (агрегация daily).",
            desc_en="Indicator from AWS Public Blockchain data (daily aggregation).",
            yaxis=yaxis,
            params=[
                ParamSpec(
                    key="_dummy",
                    kind="bool",
                    default=False,
                    label_ru="",
                    label_en="",
                )
            ],
            compute=_compute,
        )
    )


# Register a minimal starter set (matches app.py today)
_make_daily_indicator(
    ind_id="aws_tx_count",
    stem="tx_count",
    title_ru="AWS: Tx count (daily)",
    title_en="AWS: Tx count (daily)",
)
_make_daily_indicator(
    ind_id="aws_fees_btc",
    stem="fees_btc",
    title_ru="AWS: Fees (BTC/day)",
    title_en="AWS: Fees (BTC/day)",
)
_make_daily_indicator(
    ind_id="aws_feerate_p90_sat_vb",
    stem="feerate_p90_sat_vb",
    title_ru="AWS: Fee rate P90 (sat/vB)",
    title_en="AWS: Fee rate P90 (sat/vB)",
)
_make_daily_indicator(
    ind_id="aws_vsize_sum",
    stem="vsize_sum",
    title_ru="AWS: vsize sum/day",
    title_en="AWS: vsize sum/day",
)
