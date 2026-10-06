# backtest_runner.py
from __future__ import annotations

import glob
import hashlib
import importlib.util
import inspect
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Optional, Tuple

import numpy as np
import pandas as pd

import core_yaml


@dataclass
class BacktestResult:
    trades: pd.DataFrame
    equity: pd.DataFrame
    metrics: Dict[str, Any]


def normalize_result(res_any: Any) -> BacktestResult:
    if isinstance(res_any, BacktestResult):
        return res_any
    if isinstance(res_any, core_yaml.BacktestResult):
        return BacktestResult(trades=res_any.trades, equity=res_any.equity, metrics=res_any.metrics)

    if hasattr(res_any, "trades") and hasattr(res_any, "equity") and hasattr(res_any, "metrics"):
        t = res_any.trades
        e = res_any.equity
        m = res_any.metrics
        if not isinstance(t, pd.DataFrame):
            t = pd.DataFrame(t)
        if not isinstance(e, pd.DataFrame):
            e = pd.DataFrame(e)
        if not isinstance(m, dict):
            m = dict(m)
        return BacktestResult(trades=t, equity=e, metrics=m)

    if isinstance(res_any, dict):
        t = res_any.get("trades", pd.DataFrame())
        e = res_any.get("equity", pd.DataFrame())
        m = res_any.get("metrics", {})
        if not isinstance(t, pd.DataFrame):
            t = pd.DataFrame(t)
        if not isinstance(e, pd.DataFrame):
            e = pd.DataFrame(e)
        if not isinstance(m, dict):
            m = dict(m)
        return BacktestResult(trades=t, equity=e, metrics=m)

    raise ValueError("Python strategy returned unsupported result format.")


def make_hash(text: str) -> str:
    return hashlib.sha1((text or "").encode("utf-8", errors="ignore")).hexdigest()


def make_bt_key(data_sig: Tuple[Any, ...], strategy_sig: Tuple[Any, ...], run_sig: Tuple[Any, ...]) -> str:
    raw = repr((data_sig, strategy_sig, run_sig)).encode("utf-8", errors="ignore")
    return hashlib.sha1(raw).hexdigest()


def list_py_strategies(strategies_dir: str) -> Dict[str, str]:
    pyfiles = sorted(glob.glob(os.path.join(strategies_dir, "*.py")))
    pyfiles = [p for p in pyfiles if os.path.basename(p) != "__init__.py"]
    return {os.path.basename(p): p for p in pyfiles}


def load_py_strategy_module(path: str) -> ModuleType:
    p = Path(path).resolve()
    mtime = int(p.stat().st_mtime_ns)
    mod_name = f"mybot_strategy_{p.stem}_{mtime}"

    spec = importlib.util.spec_from_file_location(mod_name, str(p))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load strategy module: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def validate_py_strategy(mod: ModuleType) -> Dict[str, Any]:
    if not hasattr(mod, "STRATEGY_META") or not isinstance(mod.STRATEGY_META, dict):
        raise ValueError("Strategy must define STRATEGY_META: dict")
    if not hasattr(mod, "run") or not callable(mod.run):
        raise ValueError("Strategy must define run(df, **kwargs) function")

    meta = mod.STRATEGY_META.copy()
    meta.setdefault("name", getattr(mod, "__name__", "Unnamed"))
    meta.setdefault("id", meta["name"])
    meta.setdefault("description", "")
    meta.setdefault("requires_pine_text", bool(getattr(mod, "REQUIRES_PINE_TEXT", False)))
    return meta


def trim_result_to_range(res: BacktestResult, dt_from: Optional[pd.Timestamp], dt_to: Optional[pd.Timestamp], timeframe: str) -> BacktestResult:
    eq = res.equity.copy()
    if "timestamp" in eq.columns:
        eq["timestamp"] = pd.to_datetime(eq["timestamp"], utc=True, errors="coerce")
        eq = eq.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)

    trd = res.trades.copy()
    for c in ["entry_time", "exit_time"]:
        if c in trd.columns:
            trd[c] = pd.to_datetime(trd[c], utc=True, errors="coerce")

    if dt_from is not None and dt_to is not None and "timestamp" in eq.columns and len(eq) > 0:
        eq = eq[(eq["timestamp"] >= dt_from) & (eq["timestamp"] <= dt_to)].copy().reset_index(drop=True)

    if dt_from is not None and dt_to is not None and "exit_time" in trd.columns and len(trd) > 0:
        trd = trd[(trd["exit_time"] >= dt_from) & (trd["exit_time"] <= dt_to)].copy().reset_index(drop=True)

    if len(eq) == 0:
        metrics = dict(res.metrics or {})
        metrics.update({"Final Equity": 1.0, "Total Return": 0.0, "Max Drawdown": 0.0, "Sharpe (rough)": 0.0, "Trades": 0.0, "Win Rate": 0.0})
        return BacktestResult(trades=trd, equity=eq, metrics=metrics)

    series = eq["equity"].astype(float)
    rets = series.pct_change().replace([np.inf, -np.inf], np.nan).fillna(0.0)
    peak = series.cummax()
    dd = (series / peak) - 1.0
    dd_min = float(dd.min()) if len(dd) else 0.0

    ann = core_yaml.annualization_factor(timeframe)
    sharpe = 0.0
    if rets.std(ddof=0) > 0:
        sharpe = float((rets.mean() / rets.std(ddof=0)) * ann)

    win_rate = float((trd["gross_return"] > 1.0).mean()) if (len(trd) > 0 and "gross_return" in trd.columns) else 0.0

    metrics = dict(res.metrics or {})
    metrics.update(
        {
            "Final Equity": float(series.iloc[-1]),
            "Total Return": float(series.iloc[-1] - 1.0),
            "Max Drawdown": float(dd_min),
            "Sharpe (rough)": float(sharpe),
            "Trades": float(len(trd)),
            "Win Rate": float(win_rate),
        }
    )
    return BacktestResult(trades=trd, equity=eq, metrics=metrics)


def run_backtest(
    *,
    df_warm: pd.DataFrame,
    data_sig: Tuple[Any, ...],
    timeframe: str,
    dt_from_run: pd.Timestamp,
    dt_to_run: pd.Timestamp,
    warmup_bars: int,
    strategy_lang: str,  # "YAML" | "Python"
    yaml_text: str,
    strategies_dir: str,
    py_select_value: Optional[str],
    overrides: Dict[str, Any],
    pine_text: str,
    bt_cache: Dict[str, BacktestResult],
) -> BacktestResult:
    """
    Возвращает НОРМАЛИЗОВАННЫЙ и TRIM-нутый результат (BacktestResult).
    Кэширует по ключу. Не трогает UI.
    """
    tfv = timeframe

    if strategy_lang == "YAML":
        cfg = core_yaml.load_yaml_text(yaml_text)
        strategy_sig = ("YAML", make_hash(yaml_text))
        run_sig = (tfv, str(dt_from_run), str(dt_to_run), int(warmup_bars))
        key = make_bt_key(data_sig, strategy_sig, run_sig)

        if key in bt_cache:
            res = bt_cache[key]
        else:
            res0 = core_yaml.run_backtest_yaml(
                df_warm=df_warm,
                cfg=cfg,
                timeframe=tfv,
                active_from=dt_from_run,
                active_to=dt_to_run,
                intrabar_priority="sl",
            )
            res = normalize_result(res0)
            bt_cache[key] = res

        return trim_result_to_range(res, dt_from_run, dt_to_run, tfv)

    # Python
    d = strategies_dir.strip() or "strategies"
    mp = list_py_strategies(d)
    if not py_select_value or py_select_value not in mp:
        raise ValueError("Выберите Python стратегию.")

    spath = mp[py_select_value]
    mod = load_py_strategy_module(spath)
    meta = validate_py_strategy(mod)
    sig = inspect.signature(mod.run)

    run_kwargs: Dict[str, Any] = {}
    if "timeframe" in sig.parameters:
        run_kwargs["timeframe"] = tfv
    for k, v in overrides.items():
        if k in sig.parameters:
            run_kwargs[k] = v

    st_mtime_ns = int(Path(spath).stat().st_mtime_ns)
    strategy_sig = ("PY", meta.get("id"), os.path.basename(spath), st_mtime_ns, make_hash(pine_text))
    run_sig = (tfv, str(dt_from_run), str(dt_to_run), tuple(sorted(run_kwargs.items())))
    key = make_bt_key(data_sig, strategy_sig, run_sig)

    if key in bt_cache:
        res = bt_cache[key]
    else:
        res_any = mod.run(df_warm, **run_kwargs)
        res = normalize_result(res_any)
        bt_cache[key] = res

    return trim_result_to_range(res, dt_from_run, dt_to_run, tfv)
