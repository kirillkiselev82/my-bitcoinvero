from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

import pandas as pd


@dataclass(frozen=True)
class ParamSpec:
    """UI parameter description for an indicator."""

    key: str
    kind: str  # "int" | "float" | "bool" | "select"
    default: Any
    label_ru: str
    label_en: str
    help_ru: str = ""
    help_en: str = ""
    min: Optional[float] = None
    max: Optional[float] = None
    step: Optional[float] = None
    options: Optional[Sequence[Any]] = None

    def label(self, lang: str) -> str:
        return self.label_ru if (lang or "RU").upper() == "RU" else self.label_en

    def help(self, lang: str) -> str:
        return self.help_ru if (lang or "RU").upper() == "RU" else self.help_en


@dataclass(frozen=True)
class IndicatorSpec:
    id: str
    title_ru: str
    title_en: str
    desc_ru: str = ""
    desc_en: str = ""
    params: List[ParamSpec] = field(default_factory=list)
    yaxis: str = "y"  # "y" | "y2"
    compute: Callable[[pd.DataFrame, Dict[str, Any]], "IndicatorOutput"] | None = None

    def title(self, lang: str) -> str:
        return self.title_ru if (lang or "RU").upper() == "RU" else self.title_en

    def desc(self, lang: str) -> str:
        return self.desc_ru if (lang or "RU").upper() == "RU" else self.desc_en


@dataclass
class IndicatorOutput:
    traces: List[Any] = field(default_factory=list)
    layout: Dict[str, Any] = field(default_factory=dict)
    # будущее (для YAML): индикаторы смогут отдавать вычисленные серии/колонки
    series: Dict[str, pd.Series] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


_REGISTRY: Dict[str, IndicatorSpec] = {}


def register(spec: IndicatorSpec) -> None:
    if not isinstance(spec, IndicatorSpec):
        raise TypeError("spec must be IndicatorSpec")
    if not spec.id:
        raise ValueError("IndicatorSpec.id must be non-empty")
    if spec.compute is None:
        raise ValueError(f"IndicatorSpec.compute is required for {spec.id}")
    _REGISTRY[spec.id] = spec


def get(spec_id: str) -> Optional[IndicatorSpec]:
    return _REGISTRY.get(str(spec_id))


def list_specs() -> List[IndicatorSpec]:
    return sorted(_REGISTRY.values(), key=lambda s: s.id)


def default_params(spec_id: str) -> Dict[str, Any]:
    spec = get(spec_id)
    if spec is None:
        return {}
    return {p.key: p.default for p in spec.params}

