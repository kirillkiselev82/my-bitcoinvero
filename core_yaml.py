# core_yaml.py
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

try:
    import yaml  # pip install pyyaml
except Exception:
    yaml = None


@dataclass
class BacktestResult:
    trades: pd.DataFrame
    equity: pd.DataFrame
    metrics: Dict[str, Any]


DEFAULT_YAML = """\
name: "SMA Cross (пример)"
description: "Пример YAML стратегии. Long-only."
timeframe: "15m"
fees: 0.001
slippage: 0.0002

indicators:
  - name: "sma_fast"
    type: "sma"
    source: "close"
    length: 20
  - name: "sma_slow"
    type: "sma"
    source: "close"
    length: 50

signals:
  entry: "sma_fast > sma_slow"
  exit: "sma_fast < sma_slow"

execution:
  price: "next_open"

risk:
  position_size_pct: 100
  stop_loss_pct: 0.0
  take_profit_pct: 0.0
  fee_pct: 0.0
"""


def load_yaml_text(text: str) -> Dict[str, Any]:
    if yaml is None:
        raise RuntimeError("pyyaml не установлен. Установите: pip install pyyaml")
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError("YAML root должен быть mapping (dict).")
    return data


def sma(s: pd.Series, length: int) -> pd.Series:
    return s.rolling(length, min_periods=length).mean()


def ema(s: pd.Series, length: int) -> pd.Series:
    return s.ewm(span=length, adjust=False, min_periods=length).mean()


def rsi(close: pd.Series, length: int = 14) -> pd.Series:
    delta = close.diff()
    gain = delta.where(delta > 0, 0.0)
    loss = -delta.where(delta < 0, 0.0)
    avg_gain = gain.ewm(alpha=1 / length, adjust=False, min_periods=length).mean()
    avg_loss = loss.ewm(alpha=1 / length, adjust=False, min_periods=length).mean()
    rs = avg_gain / avg_loss.replace(0, np.nan)
    return 100 - (100 / (1 + rs))


INDICATOR_FUNCS = {"sma": sma, "ema": ema, "rsi": rsi}


def apply_indicators(df: pd.DataFrame, cfg: Dict[str, Any]) -> pd.DataFrame:
    indicators = cfg.get("indicators", {}) or {}
    out = df.copy()

    if isinstance(indicators, dict):
        indicators_list = []
        for name, spec in indicators.items():
            if not isinstance(spec, dict):
                raise ValueError(f"Indicator '{name}' должен быть mapping.")
            d = dict(spec)
            d["name"] = name
            indicators_list.append(d)
    elif isinstance(indicators, list):
        indicators_list = indicators
    else:
        raise ValueError("indicators должен быть list или dict")

    for ind in indicators_list:
        if not isinstance(ind, dict):
            raise ValueError("Каждый indicator должен быть mapping.")
        name = ind.get("name")
        itype = (ind.get("type") or "").lower()
        source = ind.get("source", "close")

        if not name or not itype:
            raise ValueError(f"Indicator должен иметь name/type. Получили: {ind}")
        if itype not in INDICATOR_FUNCS:
            raise ValueError(f"Unsupported indicator type: {itype}. Supported: {sorted(INDICATOR_FUNCS)}")
        if source not in out.columns:
            raise ValueError(f"Indicator source '{source}' отсутствует в df columns: {list(out.columns)}")

        if itype in ("sma", "ema"):
            length = int(ind.get("length", 0))
            if length <= 0:
                raise ValueError(f"Indicator {name}: length должен быть > 0")
            out[name] = INDICATOR_FUNCS[itype](out[source], length)
        elif itype == "rsi":
            length = int(ind.get("length", 14))
            out[name] = INDICATOR_FUNCS[itype](out[source], length)

    return out


def annualization_factor(timeframe: str) -> float:
    tf = timeframe
    if tf.endswith("m"):
        minutes = int(tf[:-1])
        bars_per_day = (24 * 60) / minutes
        return math.sqrt(bars_per_day * 365)
    if tf.endswith("H"):
        hours = int(tf[:-1])
        bars_per_day = 24 / hours
        return math.sqrt(bars_per_day * 365)
    if tf == "1D":
        return math.sqrt(365)
    if tf == "1W":
        return math.sqrt(52)
    if tf == "1M":
        return math.sqrt(12)
    if tf == "3M":
        return math.sqrt(4)
    return math.sqrt(365)


def compute_drawdown(equity: pd.Series) -> Tuple[pd.Series, float]:
    peak = equity.cummax()
    dd = (equity / peak) - 1.0
    return dd, float(dd.min()) if len(dd) else 0.0


def _cross_up(a: pd.Series, b: pd.Series) -> pd.Series:
    return (a > b) & (a.shift(1) <= b.shift(1))


def _cross_down(a: pd.Series, b: pd.Series) -> pd.Series:
    return (a < b) & (a.shift(1) >= b.shift(1))


_cross_call_re = re.compile(r"(cross_up|cross_down)\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*\)")


def eval_condition(expr: str, df: pd.DataFrame) -> pd.Series:
    expr = (expr or "").strip()
    if not expr:
        return pd.Series([False] * len(df), index=df.index)

    matches = list(_cross_call_re.finditer(expr))
    if matches:
        tmp_cols = {}
        parts = []
        last = 0

        for idx, m in enumerate(matches):
            fn, a, b = m.group(1), m.group(2), m.group(3)
            if a not in df.columns or b not in df.columns:
                raise ValueError(f"Unknown series in {m.group(0)}. Have columns: {list(df.columns)}")

            tmp_name = f"__{fn}_{idx}"
            if fn == "cross_up":
                tmp_cols[tmp_name] = _cross_up(df[a], df[b]).fillna(False).astype(bool)
            else:
                tmp_cols[tmp_name] = _cross_down(df[a], df[b]).fillna(False).astype(bool)

            parts.append(expr[last:m.start()])
            parts.append(tmp_name)
            last = m.end()

        parts.append(expr[last:])
        expr2 = "".join(parts)

        tmp_df = df.copy()
        for k, v in tmp_cols.items():
            tmp_df[k] = v

        s = tmp_df.eval(expr2, engine="python")
    else:
        s = df.eval(expr, engine="python")

    if not isinstance(s, pd.Series):
        s = pd.Series([bool(s)] * len(df), index=df.index)
    return s.fillna(False).astype(bool)


def run_backtest_yaml(
    df_warm: pd.DataFrame,
    cfg: Dict[str, Any],
    timeframe: str,
    active_from: Optional[pd.Timestamp],
    active_to: Optional[pd.Timestamp],
    intrabar_priority: str = "sl",
    initial_capital_usd: float = 1000.0,
) -> BacktestResult:
    df = df_warm.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["timestamp", "open", "high", "low", "close"]).sort_values("timestamp").reset_index(drop=True)

    if len(df) < 10:
        raise ValueError("Недостаточно данных для бэктеста.")

    df = apply_indicators(df, cfg)

    signals = cfg.get("signals", {}) or {}
    entry_expr = signals.get("entry")
    exit_expr = signals.get("exit")
    if not entry_expr or not exit_expr:
        raise ValueError("YAML: нужны signals.entry и signals.exit")

    entry_sig = eval_condition(entry_expr, df)
    exit_sig = eval_condition(exit_expr, df)

    exec_cfg = cfg.get("execution", {}) or {}
    price_mode = (exec_cfg.get("price", "next_open") or "next_open").lower()
    if price_mode not in ("close", "next_open"):
        price_mode = "next_open"

    fees = float(cfg.get("fees", 0.0) or 0.0)
    slippage = float(cfg.get("slippage", 0.0) or 0.0)

    risk = cfg.get("risk", {}) or {}
    pos_pct = float(risk.get("position_size_pct", 100.0)) / 100.0
    sl_pct = float(risk.get("stop_loss_pct", 0.0)) / 100.0
    tp_pct = float(risk.get("take_profit_pct", 0.0)) / 100.0
    fee_pct = float(risk.get("fee_pct", 0.0)) / 100.0

    fee_fraction = fee_pct if fee_pct > 0 else fees

    if price_mode == "close":
        buy_px = df["close"]
        sell_px = df["close"]
    else:
        buy_px = df["open"].shift(-1)
        sell_px = df["open"].shift(-1)

    valid = ~buy_px.isna() & ~sell_px.isna()
    df = df.loc[valid].reset_index(drop=True)
    entry_sig = entry_sig.loc[valid].reset_index(drop=True)
    exit_sig = exit_sig.loc[valid].reset_index(drop=True)
    buy_px = buy_px.loc[valid].reset_index(drop=True)
    sell_px = sell_px.loc[valid].reset_index(drop=True)

    if active_from is None:
        active_from = df["timestamp"].min()
    if active_to is None:
        active_to = df["timestamp"].max()

    active_from = pd.to_datetime(active_from, utc=True, errors="coerce")
    active_to = pd.to_datetime(active_to, utc=True, errors="coerce")

    mask_active = (df["timestamp"] >= active_from) & (df["timestamp"] <= active_to)
    if not mask_active.any():
        raise ValueError("В выбранном периоде нет данных.")

    start_i = int(mask_active.idxmax())
    end_i = int(mask_active[mask_active].index.max())

    pr = (intrabar_priority or "sl").lower()
    if pr not in ("sl", "tp", "worst", "best"):
        pr = "sl"

    # IMPORTANT: internal normalization = 1.0 start
    cash = 1.0
    units = 0.0
    entry_price: Optional[float] = None
    entry_time = None
    in_pos = False

    equity_curve: List[Tuple[pd.Timestamp, float]] = []
    trades: List[Dict[str, Any]] = []

    for i in range(start_i, end_i + 1):
        ts = df.loc[i, "timestamp"]
        px_mtm = float(df.loc[i, "close"])
        equity = cash + units * px_mtm
        equity_curve.append((ts, equity))

        if in_pos and entry_price is not None:
            lo = float(df.loc[i, "low"])
            hi = float(df.loc[i, "high"])

            stop_price = entry_price * (1.0 - sl_pct) if sl_pct > 0 else None
            take_price = entry_price * (1.0 + tp_pct) if tp_pct > 0 else None

            hit_sl = stop_price is not None and lo <= stop_price
            hit_tp = take_price is not None and hi >= take_price

            if hit_sl or hit_tp:
                if hit_sl and hit_tp:
                    choose_tp = pr in ("tp", "best")
                    if pr == "worst":
                        choose_tp = False
                else:
                    choose_tp = hit_tp

                reason = "TP" if choose_tp else "SL"
                exit_px = take_price if choose_tp else stop_price
                if exit_px is None or exit_px <= 0:
                    exit_px = px_mtm

                exit_price = float(exit_px) * (1.0 - slippage)
                gross = units * exit_price
                fee_amt = gross * fee_fraction
                cash = cash + (gross - fee_amt)

                trades.append(
                    {
                        "side": 1,
                        "close_reason": reason,
                        "entry_time": entry_time,
                        "exit_time": ts,
                        "entry_price": float(entry_price),
                        "exit_price": float(exit_price),
                        "reason": reason,
                        "gross_return": float(exit_price / entry_price) if entry_price else 1.0,
                        "equity": float(cash),
                    }
                )

                units = 0.0
                entry_price = None
                entry_time = None
                in_pos = False
                continue

        if (not in_pos) and bool(entry_sig.iloc[i]):
            px = float(buy_px.iloc[i])
            entry_px = px * (1.0 + slippage)
            fee_amt = cash * fee_fraction
            cash_net = max(0.0, cash - fee_amt)
            alloc = cash_net * pos_pct
            units = alloc / entry_px if entry_px > 0 else 0.0
            cash = cash_net - alloc
            entry_price = float(entry_px)
            entry_time = ts
            in_pos = True
            continue

        if in_pos and bool(exit_sig.iloc[i]):
            px = float(sell_px.iloc[i])
            exit_price = px * (1.0 - slippage)

            gross = units * exit_price
            fee_amt = gross * fee_fraction
            cash += (gross - fee_amt)

            trades.append(
                {
                    "side": 1,
                    "close_reason": "SIGNAL",
                    "entry_time": entry_time,
                    "exit_time": ts,
                    "entry_price": float(entry_price) if entry_price is not None else np.nan,
                    "exit_price": float(exit_price),
                    "reason": "SIGNAL",
                    "gross_return": float(exit_price / entry_price) if entry_price else 1.0,
                    "equity": float(cash),
                }
            )

            units = 0.0
            entry_price = None
            entry_time = None
            in_pos = False

    equity_df = pd.DataFrame(equity_curve, columns=["timestamp", "equity"]).dropna()
    equity_df["timestamp"] = pd.to_datetime(equity_df["timestamp"], utc=True, errors="coerce")
    equity_df = equity_df.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)

    trades_df = pd.DataFrame(trades)
    if len(trades_df) > 0:
        trades_df["entry_time"] = pd.to_datetime(trades_df["entry_time"], utc=True, errors="coerce")
        trades_df["exit_time"] = pd.to_datetime(trades_df["exit_time"], utc=True, errors="coerce")

    eq = equity_df["equity"]
    rets = eq.pct_change().replace([np.inf, -np.inf], np.nan).fillna(0.0)
    _, dd_min = compute_drawdown(eq)

    ann = annualization_factor(timeframe)
    sharpe = 0.0
    if rets.std(ddof=0) > 0:
        sharpe = float((rets.mean() / rets.std(ddof=0)) * ann)

    total_return = float(eq.iloc[-1] - 1.0) if len(eq) else 0.0
    n_trades = int(len(trades_df))
    win_rate = float((trades_df["gross_return"] > 1.0).mean()) if n_trades > 0 else 0.0

    final_equity = float(eq.iloc[-1]) if len(eq) else 1.0
    init_cap = float(initial_capital_usd or 1000.0)

    metrics = {
        "Final Equity": final_equity,
        "Total Return": total_return,
        "Max Drawdown": float(dd_min),
        "Sharpe (rough)": sharpe,
        "Trades": float(n_trades),
        "Win Rate": win_rate,
        "Fee": float(fee_fraction),
        "Slippage": float(slippage),
        "Execution": "next_open" if price_mode == "next_open" else "close",
        "Params": {
            "intrabar_priority": pr,
            "active_from": str(active_from),
            "active_to": str(active_to),
        },
        "Initial Capital (USD)": init_cap,
        "Final Balance (USD)": float(init_cap * final_equity),
    }

    return BacktestResult(trades=trades_df, equity=equity_df, metrics=metrics)

