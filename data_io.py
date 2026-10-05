# data_io.py
from __future__ import annotations

import hashlib
import io
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd


# ---------------- Date parsing (YYYY-MM-DD treated as "whole day") ----------------

_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _parse_user_dt(text: str, *, is_end: bool) -> Tuple[Optional[pd.Timestamp], bool, Optional[str]]:
    """
    Returns (dt, is_exclusive_end, warn)

    Rules:
      - empty -> (None, False, None)
      - 'YYYY-MM-DD' (date-only):
          start: 00:00 inclusive
          end:   next day 00:00 exclusive  (so user gets "end of day")
      - otherwise: parse as datetime; end is inclusive (<=)
    """
    s = (text or "").strip()
    if not s:
        return None, False, None

    if _DATE_ONLY_RE.match(s):
        try:
            dt = pd.Timestamp(s, tz="UTC")
            if is_end:
                return dt + pd.Timedelta(days=1), True, None  # exclusive end
            return dt, False, None
        except Exception as e:
            return None, False, "Некорректная дата: %s (%s)" % (s, e)

    try:
        dt = pd.to_datetime(s, utc=True, errors="raise")
        if isinstance(dt, pd.DatetimeIndex):
            dt = dt[0]
        return pd.Timestamp(dt), False, None
    except Exception as e:
        return None, False, "Некорректная дата/время: %s (%s)" % (s, e)


def _apply_time_range_filter(
    df: pd.DataFrame,
    *,
    ts_col: str,
    date_from_text: str,
    date_to_text: str,
) -> Tuple[pd.DataFrame, Optional[str]]:
    """
    Applies user time range filter to df using ts_col (UTC).
    End date-only is treated as end-exclusive (next day 00:00).
    """
    warn_parts: List[str] = []

    dt_from, _from_excl, w1 = _parse_user_dt(date_from_text, is_end=False)
    dt_to, to_excl, w2 = _parse_user_dt(date_to_text, is_end=True)

    if w1:
        warn_parts.append(w1)
    if w2:
        warn_parts.append(w2)

    out = df
    if dt_from is not None:
        out = out[out[ts_col] >= dt_from]

    if dt_to is not None:
        if to_excl:
            out = out[out[ts_col] < dt_to]   # exclusive end
        else:
            out = out[out[ts_col] <= dt_to]  # inclusive end for datetime

    warn = "; ".join(warn_parts) if warn_parts else None
    return out, warn


# ---------------- Small utilities expected by app.py / plots.py ----------------

def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def refresh_csv_options(data_dir: str) -> List[str]:
    """Return list of *.csv filenames (not full paths) sorted."""
    d = (data_dir or "").strip()
    if not d:
        return []
    if not os.path.isdir(d):
        return []
    out: List[str] = []
    for fn in os.listdir(d):
        if fn.lower().endswith(".csv") and os.path.isfile(os.path.join(d, fn)):
            out.append(fn)
    out.sort()
    return out


def pick_csv_for_tf(tf: str, options: List[str]) -> Optional[str]:
    """
    Heuristic: pick file whose name contains tf token.
    Examples: tf=1H -> btc_usdt_1H.csv / btc_1h.csv
    """
    if not options:
        return None
    t = (tf or "").strip()
    if not t:
        return options[0]

    t_norm = t.strip()
    variants = {t_norm, t_norm.lower(), t_norm.upper()}

    if t_norm.endswith(("H", "D", "W", "M", "m")):
        variants.add(t_norm[:-1] + t_norm[-1].lower())
        variants.add(t_norm[:-1] + t_norm[-1].upper())

    def score(fn: str) -> Tuple[int, int]:
        name = fn.lower()
        best = 0
        for v in variants:
            vv = v.lower()
            if f"_{vv}." in name or f"_{vv}_" in name or name.endswith(f"_{vv}.csv"):
                best = max(best, 3)
            elif vv in name:
                best = max(best, 2)
        return (best, -len(fn))

    ranked = sorted(options, key=score, reverse=True)
    if score(ranked[0])[0] == 0:
        return options[0]
    return ranked[0]


def downsample_even(df: pd.DataFrame, max_points: int) -> pd.DataFrame:
    """
    Evenly downsample dataframe to at most max_points rows.
    Keeps order; used by plots.py.
    """
    try:
        n = int(max_points)
    except Exception:
        n = 0

    if not isinstance(df, pd.DataFrame) or len(df) == 0 or n <= 0:
        return df
    if len(df) <= n:
        return df

    idx = np.linspace(0, len(df) - 1, n).astype(int)
    return df.iloc[idx].reset_index(drop=True)


# ---------------- CSV loading + caching ----------------

_df_cache: Dict[str, pd.DataFrame] = {}
_sig_cache: Dict[str, Tuple[Any, ...]] = {}


def _hash_bytes_preview(b: bytes) -> str:
    if not b:
        return "0:empty"
    head = b[:4096]
    tail = b[-4096:] if len(b) > 4096 else b
    h = hashlib.sha1(head + b"::" + tail).hexdigest()
    return f"{len(b)}:{h}"


def _load_csv_from_disk(path: str) -> Tuple[pd.DataFrame, Tuple[Any, ...]]:
    st = os.stat(path)
    sig = ("disk", path, int(st.st_mtime), int(st.st_size))
    key = hashlib.sha1(repr(sig).encode("utf-8")).hexdigest()

    if key in _df_cache:
        return _df_cache[key].copy(), _sig_cache[key]

    df = pd.read_csv(path)
    _df_cache[key] = df.copy()
    _sig_cache[key] = sig
    return df, sig


def _load_csv_from_upload(upload_bytes: Optional[bytes], upload_filename: str) -> Tuple[pd.DataFrame, Tuple[Any, ...]]:
    b = upload_bytes if isinstance(upload_bytes, (bytes, bytearray)) else b""
    preview_sig = _hash_bytes_preview(b)
    sig = ("upload", (upload_filename or "").strip(), preview_sig)
    key = hashlib.sha1(repr(sig).encode("utf-8")).hexdigest()

    if key in _df_cache:
        return _df_cache[key].copy(), _sig_cache[key]

    df = pd.read_csv(io.BytesIO(b))
    _df_cache[key] = df.copy()
    _sig_cache[key] = sig
    return df, sig


def _infer_unix_unit(x: float) -> Optional[str]:
    """
    Guess unit for unix timestamps by magnitude.
    2026:
      seconds ~ 1.7e9
      ms      ~ 1.7e12
      us      ~ 1.7e15
      ns      ~ 1.7e18
    """
    ax = float(abs(x))
    if not np.isfinite(ax) or ax <= 0:
        return None
    if ax >= 1e17:
        return "ns"
    if ax >= 1e14:
        return "us"
    if ax >= 1e11:
        return "ms"
    if ax >= 1e9:
        return "s"
    return None


def _parse_timestamp_series(s: pd.Series) -> pd.Series:
    """
    Robust timestamp parser:
      - datetime strings -> pd.to_datetime(utc=True)
      - numeric unix seconds/ms/us/ns -> infer by magnitude
      - digit-strings length 10/13/16/19 -> parse as unix
    """
    if s is None:
        return pd.to_datetime(pd.Series([], dtype="datetime64[ns]"), utc=True, errors="coerce")

    # If already datetime-like (including tz-aware)
    try:
        from pandas.api.types import is_datetime64_any_dtype, is_datetime64tz_dtype
        if is_datetime64_any_dtype(s) or is_datetime64tz_dtype(s):
            return pd.to_datetime(s, utc=True, errors="coerce")
    except Exception:
        # Fallback for older pandas/numpy edge-cases
        try:
            if np.issubdtype(getattr(s, "dtype", None), np.datetime64):
                return pd.to_datetime(s, utc=True, errors="coerce")
        except Exception:
            pass

    # Try numeric
    if np.issubdtype(s.dtype, np.number):
        ser = pd.to_numeric(s, errors="coerce")
        med = float(np.nanmedian(ser.to_numpy(dtype=float))) if len(ser) else np.nan
        unit = _infer_unix_unit(med)
        if unit:
            return pd.to_datetime(ser, unit=unit, utc=True, errors="coerce")
        # fallback: normal parse
        return pd.to_datetime(ser, utc=True, errors="coerce")

    # Strings: try detect digit-only timestamps
    ss = s.astype(str).str.strip()
    # take median length for digit-only values
    digit_mask = ss.str.match(r"^\d{10,19}$", na=False)
    if digit_mask.any():
        d = pd.to_numeric(ss.where(digit_mask), errors="coerce")
        # infer by length (prefer)
        lens = ss.where(digit_mask).str.len()
        ln = int(lens.dropna().mode().iloc[0]) if len(lens.dropna()) else 0
        unit = None
        if ln == 10:
            unit = "s"
        elif ln == 13:
            unit = "ms"
        elif ln == 16:
            unit = "us"
        elif ln == 19:
            unit = "ns"
        if unit:
            dt = pd.to_datetime(d, unit=unit, utc=True, errors="coerce")
            # non-digit strings parse too
            dt2 = pd.to_datetime(ss.where(~digit_mask), utc=True, errors="coerce")
            return dt.combine_first(dt2)
        # else fallback infer by magnitude
        med = float(np.nanmedian(d.to_numpy(dtype=float))) if len(d) else np.nan
        unit2 = _infer_unix_unit(med)
        if unit2:
            dt = pd.to_datetime(d, unit=unit2, utc=True, errors="coerce")
            dt2 = pd.to_datetime(ss.where(~digit_mask), utc=True, errors="coerce")
            return dt.combine_first(dt2)

    # General string parse
    return pd.to_datetime(ss, utc=True, errors="coerce")


def _ensure_ohlc(df: pd.DataFrame) -> Tuple[pd.DataFrame, Optional[str]]:
    """
    Ensure columns: timestamp, open, high, low, close exist.
    Handles common alternatives + unix timestamps.
    """
    if not isinstance(df, pd.DataFrame) or len(df) == 0:
        return df, "Пустой CSV."

    out = df.copy()

    # timestamp column detection
    ts_candidates = ["timestamp", "time", "date", "datetime", "ts"]
    ts_col = None
    for c in ts_candidates:
        if c in out.columns:
            ts_col = c
            break
    if ts_col is None:
        ts_col = out.columns[0]

    if ts_col != "timestamp":
        out = out.rename(columns={ts_col: "timestamp"})

    # OHLC mapping common variants
    rename_map: Dict[str, str] = {}
    for need in ["open", "high", "low", "close"]:
        if need in out.columns:
            continue
        if need.upper() in out.columns:
            rename_map[need.upper()] = need
            continue
        # okx/ccxt sometimes: o,h,l,c
        short = need[0]  # o/h/l/c
        if short in out.columns and need not in out.columns:
            rename_map[short] = need
            continue
        if short.upper() in out.columns:
            rename_map[short.upper()] = need
            continue

    if rename_map:
        out = out.rename(columns=rename_map)

    # If only close exists, synthesize OHLC from close
    if "close" in out.columns and not {"open", "high", "low"}.issubset(out.columns):
        out["open"] = out.get("open", out["close"])
        out["high"] = out.get("high", out["close"])
        out["low"] = out.get("low", out["close"])

    # Convert numeric prices
    for c in ["open", "high", "low", "close"]:
        if c in out.columns:
            out[c] = pd.to_numeric(out[c], errors="coerce")

    # Robust timestamp parse (unix seconds/ms/us/ns + strings)
    out["timestamp"] = _parse_timestamp_series(out["timestamp"])

    # Basic cleanup
    out = out.dropna(subset=["timestamp"]).sort_values("timestamp")
    if "close" in out.columns:
        out = out.dropna(subset=["close"])
    else:
        return out, "CSV не содержит колонку close."

    return out, None


def _make_data_sig(base_sig: Tuple[Any, ...], df: pd.DataFrame) -> Tuple[Any, ...]:
    try:
        t0 = pd.to_datetime(df["timestamp"].min(), utc=True)
        t1 = pd.to_datetime(df["timestamp"].max(), utc=True)
        rows = int(len(df))
        cols = tuple(df.columns.tolist())
        return tuple(base_sig) + (rows, cols, str(t0), str(t1))
    except Exception:
        return tuple(base_sig)


def get_data(
    *,
    source: str,
    data_dir: str,
    csv_filename: Optional[str],
    upload_bytes: Optional[bytes],
    upload_filename: str,
    date_from_text: str,
    date_to_text: str,
    tf: str,
    warmup_bars: int,
    data_dir_default: str,
    lang_value: str = "RU",
) -> Tuple[pd.DataFrame, pd.DataFrame, Tuple[Any, ...], Optional[str]]:
    """
    Returns:
      df_warm: warmup + show window (for indicators/backtest)
      df_show: show window (for plotting)
      data_sig: signature for caching backtests
      warn: optional warning string
    """
    warn: Optional[str] = None

    src = (source or "").strip().lower()
    if src not in ("disk", "upload"):
        src = "disk"

    # Load
    try:
        if src == "upload":
            df_raw, base_sig = _load_csv_from_upload(upload_bytes, upload_filename)
        else:
            d = (data_dir or "").strip() or data_dir_default
            if not csv_filename:
                return pd.DataFrame(), pd.DataFrame(), ("disk", d, None), (
                    "CSV не выбран." if lang_value == "RU" else "No CSV selected."
                )
            path = os.path.join(d, csv_filename)
            if not os.path.exists(path):
                return pd.DataFrame(), pd.DataFrame(), ("disk", path, None), (
                    f"Файл не найден: {path}" if lang_value == "RU" else f"File not found: {path}"
                )
            df_raw, base_sig = _load_csv_from_disk(path)
    except Exception as e:
        return pd.DataFrame(), pd.DataFrame(), ("load_err",), (
            f"Ошибка загрузки CSV: {e}" if lang_value == "RU" else f"CSV load error: {e}"
        )

    # Normalize columns
    df, warn2 = _ensure_ohlc(df_raw)
    if warn2:
        warn = warn2 if not warn else (warn + " / " + warn2)

    if not isinstance(df, pd.DataFrame) or len(df) == 0:
        return pd.DataFrame(), pd.DataFrame(), _make_data_sig(base_sig, df), (
            warn or ("Нет данных." if lang_value == "RU" else "No data.")
        )

    # Apply time filter ("По дату" is end-of-day via end-exclusive)
    df_f, warn_range = _apply_time_range_filter(
        df, ts_col="timestamp", date_from_text=date_from_text, date_to_text=date_to_text
    )
    if warn_range:
        warn = warn_range if not warn else (warn + " / " + warn_range)

    if not isinstance(df_f, pd.DataFrame) or len(df_f) == 0:
        msg = (
            "По заданному диапазону данных нет. Проверьте 'С даты/По дату' и TF/CSV."
            if lang_value == "RU"
            else "No data for selected range. Check From/To and TF/CSV."
        )
        return pd.DataFrame(), pd.DataFrame(), _make_data_sig(base_sig, df), (warn + " / " + msg) if warn else msg

    df_show = df_f.reset_index(drop=True)

    # Warmup: take warmup_bars rows BEFORE df_show start from the full df (not filtered)
    try:
        warm = int(max(0, warmup_bars))
    except Exception:
        warm = 0

    if warm <= 0:
        df_warm = df_show.copy()
    else:
        t_start = df_show["timestamp"].iloc[0]
        pos = int(df["timestamp"].searchsorted(t_start, side="left"))
        warm_start = max(0, pos - warm)

        t_end = df_show["timestamp"].iloc[-1]
        end_pos = int(df["timestamp"].searchsorted(t_end, side="right"))

        df_warm = df.iloc[warm_start:end_pos].copy().reset_index(drop=True)

    data_sig = _make_data_sig(base_sig + (tf,), df_show)
    return df_warm, df_show, data_sig, warn

