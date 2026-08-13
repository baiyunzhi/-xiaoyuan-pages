from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys


FORBIDDEN = {"raw_bars", "bars", "open", "high", "low", "close", "settle", "volume", "oi", "open_interest", "member_position", "positions", "price", "lower", "upper", "change", "change_pct"}


def keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from keys(child)


def validate(path: Path, *, check_age: bool = True) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data.get("schema") == "xiaoyuan.market_screener.v3"
    assert data.get("closed_only") is True
    products = data.get("products")
    assert isinstance(products, list) and len(products) == 37
    prefixes = [row.get("prefix") for row in products]
    assert len(set(prefixes)) == 37
    assert data.get("summary", {}).get("products") == 37
    assert data.get("summary", {}).get("available", 0) >= 34
    assert data.get("identity_mode") in {
        "current_contract_refresh", "reuse_last_confirmed", "unknown"
    }
    for row in products:
        assert isinstance(row.get("active_factors"), list)
        assert row.get("active_dimensions", 0) == len(row["active_factors"])
        assert isinstance(row.get("reason_text"), str) and row["reason_text"].strip()
        assert isinstance(row.get("next_checks"), list) and row["next_checks"]
    assert not FORBIDDEN.intersection(keys(data))
    generated = datetime.fromisoformat(data["generated_at"])
    if generated.tzinfo is None:
        generated = generated.replace(tzinfo=timezone(timedelta(hours=8)))
    if check_age:
        assert datetime.now(timezone.utc) - generated.astimezone(timezone.utc) <= timedelta(hours=72)
    return data


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "market-state.json")
    result = validate(target)
    print(json.dumps({"status": "ok", "products": len(result["products"]), "as_of": result.get("as_of")}, ensure_ascii=False))
