
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd


DEFAULT_RAW_TX_BASE = Path("/opt/mybot_data/raw/aws-btc/transactions")
DEFAULT_IND_ROOT = Path("/opt/mybot_data/indicators")
DEFAULT_SCHEMA_VERSION = 1
DEFAULT_INDICATOR_VERSION = 1


@dataclass
class UpdateResult:
    window_days: int
    days_recomputed: int
    min_day: Optional[str]
    max_day: Optional[str]
    indicators_written: List[str]
    out_root: str


def _list_available_days(raw_base: Path) -> List[str]:
    # expects partition dirs: date=YYYY-MM-DD
    if not raw_base.is_dir():
        return []
    days = []
    for p in raw_base.iterdir():
        if p.is_dir() and p.name.startswith("date="):
            d = p.name.split("=", 1)[1]
            # lightweight validation
            if len(d) == 10 and d[4] == "-" and d[7] == "-":
                days.append(d)
    return sorted(set(days))


def _select_window_days(days: List[str], window_days: int) -> List[str]:
    if not days:
        return []

    # window_days semantics:
    #   0  -> recompute ALL available days (full rebuild)
    #   N>0 -> recompute last N available days (incremental)
    wd = int(window_days)
    if wd < 0:
        wd = 0
    # avoid "today" if present (often incomplete during the day)
    today = date.today().isoformat()
    filt = [d for d in days if d < today]
    if not filt:
        # if only today exists, still return it
        filt = days[:]

    # Full rebuild
    if wd == 0:
        return filt

    # Incremental window
    wd = max(1, wd)
    return filt[-wd:]


def _collect_parquet_files(raw_base: Path, days: List[str]) -> List[str]:
    files: List[str] = []
    for d in days:
        day_dir = raw_base / f"date={d}"
        if not day_dir.is_dir():
            continue
        files.extend([str(p) for p in day_dir.glob("*.parquet")])
    return sorted(files)


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _write_meta(meta_path: Path, meta: Dict) -> None:
    tmp = meta_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(meta_path)


def _write_all_formats(df: pd.DataFrame, out_base: Path, stem: str, meta: Dict) -> None:
    # df columns: d (date), value
    parquet_path = out_base / f"{stem}_daily.parquet"
    csv_path = out_base / f"{stem}_daily.csv"
    json_path = out_base / f"{stem}_daily.json"
    meta_path = out_base / "meta.json"

    _ensure_dir(out_base)

    df.to_parquet(parquet_path, index=False)
    df.to_csv(csv_path, index=False)

    # JSON array of objects: [{"d":"YYYY-MM-DD","value":...}, ...]
    json_path.write_text(df.to_json(orient="records", date_format="iso"), encoding="utf-8")

    _write_meta(meta_path, meta)


def _merge_window(existing: Optional[pd.DataFrame], patch: pd.DataFrame, key: str = "d") -> pd.DataFrame:
    if existing is None or len(existing) == 0:
        return patch.sort_values(key).reset_index(drop=True)
    # drop overlapping keys from existing, then concat
    patch_keys = set(patch[key].astype(str).tolist())
    kept = existing[~existing[key].astype(str).isin(patch_keys)].copy()
    out = pd.concat([kept, patch], ignore_index=True)
    out[key] = out[key].astype(str)
    return out.sort_values(key).reset_index(drop=True)


def update_network_daily(
    *,
    raw_tx_base: Path = DEFAULT_RAW_TX_BASE,
    ind_root: Path = DEFAULT_IND_ROOT,
    window_days: int = 31,
) -> UpdateResult:
    """
    Compute a "wide" daily network dataframe from AWS BTC transactions parquet (last N days),
    then export per-indicator datasets in:
      /opt/mybot_data/indicators/network/<indicator>/... (parquet/csv/json + meta.json)

    Incremental strategy:
      - recompute last N completed days
      - merge/overwrite those days into each indicator's history file
    """
    try:
        import duckdb  # type: ignore
    except Exception as e:
        raise RuntimeError("duckdb is required: python -m pip install duckdb") from e

    days_all = _list_available_days(raw_tx_base)
    window = _select_window_days(days_all, window_days)
    files = _collect_parquet_files(raw_tx_base, window)

    if not files:
        return UpdateResult(window_days=int(window_days), days_recomputed=0, min_day=None, max_day=None, indicators_written=[], out_root=str(ind_root))

    con = duckdb.connect()

    # Using file list rather than glob makes the recompute window precise.
    # Fee/value in source are BTC as float. Fee rate: sat/vB = fee*1e8 / vsize
    df = con.execute(
        """
        SELECT
          CAST(date AS DATE) AS d,
          COUNT(*)::BIGINT AS tx_count,

          SUM(fee) AS fees_btc,
          AVG(fee) AS fee_avg_btc,

          AVG(COALESCE(virtual_size, size)) AS vsize_avg,
          SUM(COALESCE(virtual_size, size))::BIGINT AS vsize_sum,

          SUM(input_value) AS input_value_btc,
          SUM(output_value) AS output_value_btc,

          AVG((fee*1e8) / NULLIF(COALESCE(virtual_size, size),0)) AS feerate_avg_sat_vb,
          quantile_cont((fee*1e8) / NULLIF(COALESCE(virtual_size, size),0), 0.50) AS feerate_p50_sat_vb,
          quantile_cont((fee*1e8) / NULLIF(COALESCE(virtual_size, size),0), 0.90) AS feerate_p90_sat_vb,
          quantile_cont((fee*1e8) / NULLIF(COALESCE(virtual_size, size),0), 0.99) AS feerate_p99_sat_vb
        FROM read_parquet($files, union_by_name=true)
        GROUP BY 1
        ORDER BY 1
        """,
        {"files": files},
    ).df()

    # Normalize date to string YYYY-MM-DD for stable serialization
    df["d"] = pd.to_datetime(df["d"]).dt.date.astype(str)

    # Export per-indicator
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    min_day = df["d"].min()
    max_day = df["d"].max()

    indicators = {
        "tx_count": ("network/tx_count", "tx_count", "count"),
        "fees_btc": ("network/fees_btc", "fees_btc", "btc"),
        "fee_avg_btc": ("network/fee_avg_btc", "fee_avg_btc", "btc"),
        "vsize_avg": ("network/vsize_avg", "vsize_avg", "vbytes"),
        "vsize_sum": ("network/vsize_sum", "vsize_sum", "vbytes"),
        "input_value_btc": ("network/input_value_btc", "input_value_btc", "btc"),
        "output_value_btc": ("network/output_value_btc", "output_value_btc", "btc"),
        "feerate_avg_sat_vb": ("network/feerate_avg_sat_vb", "feerate_avg_sat_vb", "sat/vb"),
        "feerate_p50_sat_vb": ("network/feerate_p50_sat_vb", "feerate_p50_sat_vb", "sat/vb"),
        "feerate_p90_sat_vb": ("network/feerate_p90_sat_vb", "feerate_p90_sat_vb", "sat/vb"),
        "feerate_p99_sat_vb": ("network/feerate_p99_sat_vb", "feerate_p99_sat_vb", "sat/vb"),
    }

    written: List[str] = []
    for col, (rel_dir, stem, unit) in indicators.items():
        out_dir = ind_root / rel_dir
        out_parquet = out_dir / f"{stem}_daily.parquet"

        patch = df[["d", col]].rename(columns={col: "value"}).copy()
        # read existing history if present
        existing = None
        if out_parquet.exists():
            try:
                existing = pd.read_parquet(out_parquet)
            except Exception:
                existing = None

        merged = _merge_window(existing, patch, key="d")

        meta = {
            "indicator_id": f"aws_{stem}_daily",
            "name": {"ru": stem, "en": stem},
            "unit": unit,
            "freq": "1D",
            "source": "aws-public-blockchain btc transactions parquet",
            "schema_version": DEFAULT_SCHEMA_VERSION,
            "indicator_version": DEFAULT_INDICATOR_VERSION,
            "updated_at": now,
            "min_date": str(merged["d"].min()) if len(merged) else None,
            "max_date": str(merged["d"].max()) if len(merged) else None,
            "recomputed_window_days": int(window_days),
        }

        _write_all_formats(merged, out_dir, stem, meta)
        written.append(stem)

    return UpdateResult(
        window_days=int(window_days),
        days_recomputed=len(window),
        min_day=min_day,
        max_day=max_day,
        indicators_written=written,
        out_root=str(ind_root),
    )
