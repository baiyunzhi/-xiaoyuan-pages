from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys


FORBIDDEN = {"raw_bars", "bars", "open", "high", "low", "close", "settle", "volume", "oi", "open_interest", "member_position", "positions", "price", "lower", "upper", "change", "change_pct"}
SCHEMA = "xiaoyuan.market_screener.v3"
SCHEMA_VERSION = "3.0"
MIN_AVAILABLE = 34
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
    assert data.get("schema") == SCHEMA
    assert data.get("schema_version") == SCHEMA_VERSION
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
    assert isinstance(available, int) and available >= MIN_AVAILABLE
    assert available == sum(row.get("pool") != "unavailable" for row in products)
    assert data.get("identity_mode") in {
        "current_contract_refresh", "reuse_last_confirmed", "unknown"
    }
    for row in products:
        factors = row.get("active_factors")
        assert isinstance(factors, list)
        assert row.get("active_dimensions", 0) == len(factors)
        assert isinstance(row.get("reason_text"), str) and row["reason_text"].strip()
        assert isinstance(row.get("next_checks"), list) and row["next_checks"]
    assert not FORBIDDEN.intersection(keys(data))

    generated = datetime.fromisoformat(data["generated_at"])
    assert generated.tzinfo is not None
    generated_utc = generated.astimezone(timezone.utc)
    now_utc = datetime.now(timezone.utc)
    assert generated_utc <= now_utc + timedelta(minutes=5)
    if check_age:
        assert now_utc - generated_utc <= timedelta(hours=72)
    return data


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "market-state.json")
    result = validate(target)
    print(json.dumps({
        "status": "ok",
        "schema": result.get("schema"),
        "products": len(result["products"]),
        "available": result.get("summary", {}).get("available"),
        "as_of": result.get("as_of"),
    }, ensure_ascii=False))
