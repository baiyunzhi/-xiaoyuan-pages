from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys


FORBIDDEN = {"raw_bars", "bars", "open", "high", "low", "close", "settle", "volume", "oi", "open_interest", "member_position", "positions", "price", "lower", "upper", "change", "change_pct"}
UPDATE_POLICY = {
    "mode": "completed_daily_once",
    "deadline_local": "23:30",
    "timezone": "Asia/Shanghai",
    "intraday_refresh": False,
}


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
    assert data.get("schema_version") == "3.0"
    assert data.get("closed_only") is True
    assert data.get("update_policy") == UPDATE_POLICY
    assert data.get("as_of") == data.get("expected_as_of")
    assert data.get("as_of")
    products = data.get("products")
    assert isinstance(products, list) and len(products) == 37
    prefixes = [row.get("prefix") for row in products]
    assert len(set(prefixes)) == 37
    assert data.get("summary", {}).get("products") == 37
    available = data.get("summary", {}).get("available")
    assert isinstance(available, int) and available >= 34
    assert available == sum(row.get("pool") != "unavailable" for row in products)
    assert not FORBIDDEN.intersection(keys(data))
    generated = datetime.fromisoformat(data["generated_at"])
    assert generated.tzinfo is not None
    if check_age:
        assert datetime.now(timezone.utc) - generated.astimezone(timezone.utc) <= timedelta(hours=72)
    return data


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "market-state.json")
    result = validate(target)
    print(json.dumps({"status": "ok", "schema": result.get("schema"), "products": len(result["products"]), "available": result.get("summary", {}).get("available"), "as_of": result.get("as_of")}, ensure_ascii=False))
