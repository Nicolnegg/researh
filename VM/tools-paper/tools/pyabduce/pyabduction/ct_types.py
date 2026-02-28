from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional


@dataclass(frozen=True)
class LeakSite:
    addr: int
    kind: str

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LeakSite":
        raw_addr = data.get("addr", data.get("instruction", 0))
        try:
            addr = int(str(raw_addr), 0)
        except ValueError:
            addr = 0
        kind = str(data.get("kind", "other")).strip().lower().replace("-", "_").replace(" ", "_")
        return cls(addr=addr, kind=kind)


@dataclass
class OracleResult:
    status: str
    leaks: List[LeakSite] = field(default_factory=list)
    raw_log: str = ""
    model: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "OracleResult":
        leaks = [LeakSite.from_dict(item) for item in data.get("leaks", [])]
        return cls(
            status=str(data.get("status", "UNKNOWN")),
            leaks=leaks,
            raw_log=str(data.get("raw_log", "")),
            model=dict(data.get("model", {})),
        )


@dataclass
class CounterexampleCT:
    pivot: Optional[str] = None
    value_lo: Optional[int] = None
    value_hi: Optional[int] = None
    leak_site: Optional[LeakSite] = None
    source: str = "derived"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CounterexampleCT":
        leak_site = data.get("leak_site")
        return cls(
            pivot=data.get("pivot"),
            value_lo=data.get("value_lo", data.get("v_lo")),
            value_hi=data.get("value_hi", data.get("v_hi")),
            leak_site=LeakSite.from_dict(leak_site) if isinstance(leak_site, Mapping) else None,
            source=str(data.get("source", "derived")),
        )
