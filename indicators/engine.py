from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from .registry import IndicatorOutput, IndicatorSpec, default_params, get, list_specs


@dataclass
class IndicatorBundle:
    traces: List[Any] = field(default_factory=list)
    layout: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


def _group_key(spec: IndicatorSpec) -> Tuple[int, str]:
    """
    Стабильная сортировка для UI.
    Чем меньше ключ — тем выше в списке.
    """
    sid = spec.id

    # built-ins — наверху
    if sid in ("sma", "ema", "bb", "vwap", "rsi", "fishnet"):
        return (0, sid)

    # onchain: onchain_<asset>_<stem>
    if sid.startswith("onchain_"):
        parts = sid.split("_", 2)
        asset = parts[1] if len(parts) > 1 else "btc"
        stem = parts[2] if len(parts) > 2 else sid

        asset_rank = {"btc": 10, "eth": 20, "xau": 30}.get(asset.lower(), 90)

        s = stem.lower()
        if any(x in s for x in ("mvrv", "cap_", "realized", "mrkt_")):
            cat = 0
        elif any(x in s for x in ("exchange", "flow_", "netflow", "sply_ex")):
            cat = 10
        elif any(x in s for x in ("adr_", "tx_", "blk_", "utxo")):
            cat = 20
        elif any(x in s for x in ("hash_", "diff_", "fee_", "iss_")):
            cat = 30
        elif any(x in s for x in ("price_", "reference_rate", "volume_")):
            cat = 40
        elif "roi_" in s:
            cat = 50
        else:
            cat = 90

        return (asset_rank + cat, sid)

    return (999, sid)


def option_map(lang: str) -> Dict[str, str]:
    """Label -> id map for UI widgets."""
    lv = (lang or "RU").upper()
    specs = list_specs()
    specs.sort(key=lambda s: (_group_key(s), s.title(lv)))
    m: Dict[str, str] = {}
    for spec in specs:
        m[spec.title(lv)] = spec.id
    return m


def merge_params(spec: IndicatorSpec, user_params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    base = default_params(spec.id)
    if user_params:
        for k, v in user_params.items():
            if str(k).startswith("_"):
                continue
            base[str(k)] = v
    return base


def compute_bundle(
    df_show: pd.DataFrame,
    selected_ids: List[str],
    params_by_id: Optional[Dict[str, Dict[str, Any]]] = None,
    *,
    max_points: int = 8000,
) -> IndicatorBundle:
    """Compute traces/layout for selected indicators.

    - Does NOT mutate df_show.
    - Merges layout dict; shapes are appended.
    - Adds _max_points reserved param.
    """
    bundle = IndicatorBundle()

    if not selected_ids:
        return bundle

    params_by_id = params_by_id or {}

    for ind_id in selected_ids:
        spec = get(ind_id)
        if spec is None:
            continue

        params = merge_params(spec, params_by_id.get(ind_id))
        params["_max_points"] = int(max_points)

        try:
            out = spec.compute(df_show, params)  # type: ignore[misc]
        except Exception as e:
            bundle.warnings.append(f"{spec.id}: {e}")
            continue

        if not isinstance(out, IndicatorOutput):
            continue

        # traces
        if out.traces:
            bundle.traces.extend(list(out.traces))

        # layout merge
        if out.layout:
            try:
                if "shapes" in out.layout:
                    bundle.layout.setdefault("shapes", [])
                    bundle.layout["shapes"].extend(list(out.layout.get("shapes") or []))
            except Exception:
                pass

            for k, v in dict(out.layout).items():
                if k == "shapes":
                    continue
                bundle.layout[k] = v

        # warnings
        if out.warnings:
            bundle.warnings.extend([f"{spec.id}: {w}" for w in out.warnings])

    return bundle


# Ensure indicators are registered on import
from . import builtins as _builtins  # noqa: E402,F401
from . import onchain
from . import aws_network as _onchain  # noqa: E402,F401

